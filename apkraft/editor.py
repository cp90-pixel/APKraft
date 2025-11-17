"""Core APK manipulation helpers used by the CLI.

WARNING: APKraft is **not** intended to help you release modified or unlocked
versions of games. Use these utilities only for legitimate inspection,
debugging, or archival work you are legally permitted to perform. Bypassing
licenses or redistribution controls with this editor can violate the rights of
game developers and platform terms of service.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Iterable, Optional, Sequence
import warnings
import fnmatch
import hashlib
import os
import shutil
import tempfile
import zipfile

from apkutils2 import APK
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_der_pkcs7_certificates,
)

__all__ = [
    "APKEditor",
    "APKMetadata",
    "ArchiveEntry",
    "CertificateInfo",
]


@dataclass(frozen=True)
class CertificateInfo:
    """Human friendly summary of a signing certificate."""

    subject: str
    issuer: str
    serial_number: str
    sha1: str
    sha256: str
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True)
class APKMetadata:
    """High level information extracted from an APK."""

    package_name: Optional[str]
    version_name: Optional[str]
    version_code: Optional[str]
    min_sdk: Optional[str]
    target_sdk: Optional[str]
    file_count: int
    archive_size: int
    compressed_size: int
    uncompressed_size: int
    sha256: str
    certificates: Sequence[CertificateInfo]


@dataclass(frozen=True)
class ArchiveEntry:
    """Single member inside the APK archive."""

    name: str
    compressed_size: int
    uncompressed_size: int
    compression: str
    modified: datetime
    crc: int
    is_dir: bool


class APKEditor:
    """Lightweight utility that performs high level APK operations.

    This editor is provided for responsible research and maintenance tasks
    only. Never rely on it to package or distribute modified/unlocked versions
    of commercial games or other software you are not licensed to publish.
    """

    def __init__(self, apk_path: Path | str) -> None:
        self.apk_path = Path(apk_path).expanduser().resolve()
        if not self.apk_path.is_file():
            raise FileNotFoundError(f"APK not found: {self.apk_path}")
        self._apk = APK(str(self.apk_path))
        self._warn_release_misuse()

    # ------------------------------------------------------------------
    # Inspection helpers
    # ------------------------------------------------------------------

    def metadata(self) -> APKMetadata:
        manifest = self._apk.get_manifest() or {}
        uses_sdk = manifest.get("uses-sdk") or {}
        if isinstance(uses_sdk, list) and uses_sdk:
            uses_sdk = uses_sdk[0]

        package_name = self._manifest_attr(manifest, "package")
        version_name = self._manifest_attr(manifest, "versionName")
        version_code = self._manifest_attr(manifest, "versionCode")
        min_sdk = self._manifest_attr(uses_sdk or {}, "minSdkVersion")
        target_sdk = self._manifest_attr(uses_sdk or {}, "targetSdkVersion")

        archive_size = self.apk_path.stat().st_size
        sha256 = self._sha256()

        with zipfile.ZipFile(self.apk_path, "r") as zf:
            infos = zf.infolist()
            file_count = len(infos)
            compressed = sum(info.compress_size for info in infos)
            uncompressed = sum(info.file_size for info in infos)

        certificates = tuple(self._read_certificates())

        return APKMetadata(
            package_name=package_name,
            version_name=version_name,
            version_code=version_code,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            file_count=file_count,
            archive_size=archive_size,
            compressed_size=compressed,
            uncompressed_size=uncompressed,
            sha256=sha256,
            certificates=certificates,
        )

    def manifest_xml(self) -> str:
        manifest = self._apk.get_org_manifest()
        if not manifest:
            raise RuntimeError("This APK does not expose AndroidManifest.xml")
        return manifest

    def list_entries(self,
                     pattern: Optional[str] = None,
                     show_dirs: bool = True) -> list[ArchiveEntry]:
        entries: list[ArchiveEntry] = []

        with zipfile.ZipFile(self.apk_path, "r") as zf:
            for info in zf.infolist():
                if not show_dirs and info.is_dir():
                    continue
                if pattern and not fnmatch.fnmatch(info.filename, pattern):
                    continue
                entries.append(self._to_archive_entry(info))
        return entries

    # ------------------------------------------------------------------
    # File level editing helpers
    # ------------------------------------------------------------------

    def extract(self, member: str, destination: Path) -> Path:
        member = self._normalize_member(member)
        destination = destination.expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(self.apk_path, "r") as zf:
            info = self._get_member_info(zf, member)
            if info is None:
                raise FileNotFoundError(f"{member} not found inside APK")
            target = destination / info.filename
            self._safe_extract(zf, info, target, destination)
            return target.resolve()

    def extract_all(self, destination: Path) -> Path:
        destination = destination.expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            for info in zf.infolist():
                target = destination / info.filename
                self._safe_extract(zf, info, target, destination)
        return destination

    def replace_file(self,
                     member: str,
                     new_file: Path,
                     output_path: Optional[Path] = None,
                     in_place: bool = False,
                     keep_backup: bool = True) -> Path:
        member = self._normalize_member(member)
        new_data = Path(new_file).read_bytes()

        def writer(src: zipfile.ZipFile, dst: zipfile.ZipFile) -> None:
            replaced = False
            for info in src.infolist():
                data = new_data if info.filename == member else src.read(info.filename)
                if info.filename == member:
                    replaced = True
                self._write_entry(dst, info, data)
            if not replaced:
                raise FileNotFoundError(f"{member} not found inside APK")

        return self._rewrite(writer, output_path, in_place, keep_backup)

    def delete_file(self,
                    member: str,
                    output_path: Optional[Path] = None,
                    in_place: bool = False,
                    keep_backup: bool = True) -> Path:
        member = self._normalize_member(member)

        def writer(src: zipfile.ZipFile, dst: zipfile.ZipFile) -> None:
            deleted = False
            for info in src.infolist():
                if info.filename == member or info.filename.startswith(member + "/"):
                    deleted = True
                    continue
                self._write_entry(dst, info, src.read(info.filename))
            if not deleted:
                raise FileNotFoundError(f"{member} not found inside APK")

        return self._rewrite(writer, output_path, in_place, keep_backup)

    def add_file(self,
                 filesystem_path: Path,
                 archive_path: str,
                 output_path: Optional[Path] = None,
                 in_place: bool = False,
                 keep_backup: bool = True) -> Path:
        archive_path = self._normalize_member(archive_path)
        payload = Path(filesystem_path)
        if payload.is_dir():
            raise IsADirectoryError("payload path cannot be a directory")
        payload_bytes = payload.read_bytes()

        def writer(src: zipfile.ZipFile, dst: zipfile.ZipFile) -> None:
            for info in src.infolist():
                self._write_entry(dst, info, src.read(info.filename))
            info = zipfile.ZipInfo(archive_path)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            dst.writestr(info, payload_bytes)

        return self._rewrite(writer, output_path, in_place, keep_backup)

    @staticmethod
    def repack_directory(directory: Path,
                         output_apk: Path,
                         compression: int = zipfile.ZIP_DEFLATED) -> Path:
        directory = directory.expanduser().resolve()
        if not directory.is_dir():
            raise NotADirectoryError(directory)
        output_apk = output_apk.expanduser().resolve()
        output_apk.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(output_apk, "w", compression=compression) as zf:
            for file_path in sorted(directory.rglob("*")):
                if file_path.is_dir():
                    continue
                arcname = file_path.relative_to(directory).as_posix()
                zf.write(file_path, arcname)
        return output_apk

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _rewrite(self,
                 writer,
                 output_path: Optional[Path],
                 in_place: bool,
                 keep_backup: bool) -> Path:
        destination = self._resolve_output_path(output_path, in_place)
        tmp_dir = Path(tempfile.mkdtemp(prefix="apkraft-"))
        tmp_file = tmp_dir / destination.name

        try:
            with zipfile.ZipFile(self.apk_path, "r") as src, \
                    zipfile.ZipFile(tmp_file, "w", compression=zipfile.ZIP_DEFLATED) as dst:
                writer(src, dst)
            return self._publish(tmp_file, destination, in_place and keep_backup)
        finally:
            if tmp_file.exists():
                tmp_file.unlink(missing_ok=True)  # type: ignore[arg-type]
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _publish(self, tmp_file: Path, destination: Path, backup: bool) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and backup and destination == self.apk_path:
            backup_path = destination.with_name(destination.name + ".bak")
            if backup_path.exists():
                backup_path.unlink()
            destination.replace(backup_path)
        elif destination.exists() and destination == self.apk_path:
            destination.unlink()

        os.replace(tmp_file, destination)
        return destination

    def _resolve_output_path(self,
                             output_path: Optional[Path],
                             in_place: bool) -> Path:
        if in_place and output_path:
            raise ValueError("Cannot combine --in-place with an explicit output path")
        if in_place:
            return self.apk_path
        if output_path:
            return output_path.expanduser().resolve()
        suffix = ''.join(self.apk_path.suffixes) or '.apk'
        candidate = self.apk_path.with_name(f"{self.apk_path.stem}.edited{suffix}")
        return candidate

    @staticmethod
    def _write_entry(dst: zipfile.ZipFile, info: zipfile.ZipInfo, data: bytes) -> None:
        new_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
        new_info.compress_type = info.compress_type
        new_info.comment = info.comment
        new_info.extra = info.extra
        new_info.internal_attr = info.internal_attr
        new_info.external_attr = info.external_attr
        new_info.flag_bits = info.flag_bits
        new_info.volume = info.volume
        new_info.create_system = info.create_system
        new_info.create_version = info.create_version
        new_info.extract_version = info.extract_version
        dst.writestr(new_info, data)

    def _sha256(self) -> str:
        digest = hashlib.sha256()
        with self.apk_path.open('rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                digest.update(chunk)
        return digest.hexdigest()

    def _read_certificates(self) -> Iterable[CertificateInfo]:
        with zipfile.ZipFile(self.apk_path, "r") as zf:
            for name in zf.namelist():
                upper = name.upper()
                if not upper.startswith("META-INF/"):
                    continue
                if not upper.endswith((".RSA", ".DSA", ".EC")):
                    continue
                data = zf.read(name)
                try:
                    certs = load_der_pkcs7_certificates(data)
                except ValueError:
                    continue
                for cert in certs:
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    serial = format(cert.serial_number, 'x').upper()
                    sha1 = cert.fingerprint(hashes.SHA1()).hex()
                    sha256 = cert.fingerprint(hashes.SHA256()).hex()
                    yield CertificateInfo(
                        subject=subject,
                        issuer=issuer,
                        serial_number=serial,
                        sha1=sha1,
                        sha256=sha256,
                        not_before=cert.not_valid_before,
                        not_after=cert.not_valid_after,
                    )
                return
        return

    @staticmethod
    def _normalize_member(member: str) -> str:
        cleaned = str(PurePosixPath(member))
        return cleaned.lstrip('./')

    @staticmethod
    def _manifest_attr(section: dict, desired: str) -> Optional[str]:
        for key, value in section.items():
            if not key.startswith('@'):
                continue
            target = key[1:]
            if target == desired:
                return value
            if target.endswith(f":{desired}"):
                return value
            if target.endswith(f"}}{desired}"):
                return value
        return None

    @staticmethod
    def _to_archive_entry(info: zipfile.ZipInfo) -> ArchiveEntry:
        compression_map = {
            zipfile.ZIP_STORED: "stored",
            zipfile.ZIP_DEFLATED: "deflated",
            zipfile.ZIP_BZIP2: "bzip2",
            zipfile.ZIP_LZMA: "lzma",
        }
        compression = compression_map.get(info.compress_type, f"{info.compress_type}")
        modified = datetime(*info.date_time)
        return ArchiveEntry(
            name=info.filename,
            compressed_size=info.compress_size,
            uncompressed_size=info.file_size,
            compression=compression,
            modified=modified,
            crc=info.CRC,
            is_dir=info.is_dir(),
        )

    @staticmethod
    def _get_member_info(zf: zipfile.ZipFile, member: str) -> Optional[zipfile.ZipInfo]:
        try:
            return zf.getinfo(member)
        except KeyError:
            return None

    @staticmethod
    def _safe_extract(zf: zipfile.ZipFile,
                      info: zipfile.ZipInfo,
                      destination: Path,
                      base_dir: Path) -> None:
        resolved_destination = destination.resolve()
        try:
            resolved_destination.relative_to(base_dir)
        except ValueError:
            raise RuntimeError(f"Blocked extracting {info.filename}: outside destination") from None
        if info.is_dir():
            resolved_destination.mkdir(parents=True, exist_ok=True)
            return
        resolved_destination.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info, 'r') as src, resolved_destination.open('wb') as dst:
            shutil.copyfileobj(src, dst)

    @staticmethod
    def _warn_release_misuse() -> None:
        warnings_list = [
            "APKraft editor must not be used to release modified or unlocked copies of commercial games.",
            "Respect the original developers' licenses and distribution agreements when working with APKraft.",
            "Distributing APKs altered with this tool can violate terms of service and the law; keep usage to legitimate testing.",
        ]
        for message in warnings_list:
            warnings.warn(message, UserWarning, stacklevel=3)

"""Command line interface for APKraft."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

import typer
from rich import box
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from . import __version__
from .agent import APKAgent, AgentRunResult, OpenRouterClient
from .editor import APKEditor, APKMetadata, ArchiveEntry, CertificateInfo

app = typer.Typer(help="Inspect and edit Android APK files.", add_completion=False)
console = Console()


@app.command()
def version() -> None:
    """Show the current APKraft version."""

    console.print(f"APKraft v{__version__}")


@app.command()
def info(apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                    help="APK to inspect"),
         json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of tables"),
         show_certs: bool = typer.Option(True, "--certs/--no-certs", help="Toggle certificate section")) -> None:
    """Display manifest, size, and signing information."""

    editor = _editor(apk)
    metadata = editor.metadata()

    if json_output:
        typer.echo(json.dumps(_metadata_to_dict(metadata), indent=2, default=str))
        return

    _render_metadata(metadata, apk)
    if show_certs and metadata.certificates:
        _render_certificates(metadata.certificates)
    elif show_certs:
        console.print("[yellow]No signing certificates found in archive[/yellow]")


@app.command(name="list")
def list_entries(apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                           help="APK to inspect"),
                pattern: Optional[str] = typer.Option(None, "--pattern", "-p",
                                                      help="Shell-style glob (e.g. res/**/*.xml)"),
                show_dirs: bool = typer.Option(True, "--dirs/--files-only",
                                                help="Include directory entries"),
                sort: str = typer.Option("name", "--sort",
                                         help="Sort key: name, size, packed, modified",
                                         metavar="{name,size,packed,modified}"),
                limit: Optional[int] = typer.Option(None, "--limit", "-n", min=1,
                                                    help="Only display the first N results")) -> None:
    """List files stored in the archive."""

    editor = _editor(apk)
    entries = editor.list_entries(pattern=pattern, show_dirs=show_dirs)

    sort_key = sort.lower()
    key_mapping = {
        "name": lambda e: e.name.lower(),
        "size": lambda e: e.uncompressed_size,
        "packed": lambda e: e.compressed_size,
        "modified": lambda e: e.modified,
    }
    if sort_key not in key_mapping:
        _fail("Unsupported sort key. Use one of: name, size, packed, modified.")
    entries.sort(key=key_mapping[sort_key], reverse=sort_key in {"size", "packed", "modified"})
    if limit is not None:
        entries = entries[:limit]

    if not entries:
        console.print("[yellow]No matching entries found[/yellow]")
        return

    table = Table(title=str(apk), box=box.SIMPLE, highlight=True)
    table.add_column("Name", overflow="fold")
    table.add_column("Size", justify="right")
    table.add_column("Packed", justify="right")
    table.add_column("Ratio", justify="right")
    table.add_column("Updated", justify="right")
    table.add_column("Compression", justify="right")

    for entry in entries:
        ratio = _compression_ratio(entry)
        table.add_row(
            entry.name,
            _fmt_bytes(entry.uncompressed_size),
            _fmt_bytes(entry.compressed_size),
            f"{ratio:.1f}%" if ratio is not None else "-",
            entry.modified.strftime("%Y-%m-%d %H:%M"),
            entry.compression,
        )
    console.print(table)


@app.command()
def extract(apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                       help="APK that contains the member"),
            member: str = typer.Argument(..., help="File inside the APK"),
            destination: Path = typer.Option(Path("."), "--dest", "-d",
                                             help="Directory to place the file in")) -> None:
    """Extract a single member from the archive."""

    editor = _editor(apk)
    target = editor.extract(member, destination)
    console.print(f"Extracted [green]{member}[/green] -> [cyan]{target}[/cyan]")


@app.command()
def unpack(apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                      help="APK to unpack"),
           destination: Path = typer.Argument(..., help="Directory that will receive the files")) -> None:
    """Extract the entire APK into a folder."""

    editor = _editor(apk)
    target_dir = editor.extract_all(destination)
    console.print(f"Unpacked into [cyan]{target_dir}[/cyan]")


@app.command()
def replace(apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                       help="APK to modify"),
            member: str = typer.Argument(..., help="Archive path to replace"),
            new_file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                           help="File that will replace the member"),
            output: Optional[Path] = typer.Option(None, "--output", "-o",
                                                  help="Location to write the patched APK"),
            in_place: bool = typer.Option(False, "--in-place", help="Overwrite the source APK"),
            keep_backup: bool = typer.Option(True, "--backup/--no-backup",
                                             help="Keep *.bak copy when patching in place")) -> None:
    """Replace a file contained in the APK."""

    editor = _editor(apk)
    result = editor.replace_file(member, new_file, output_path=output,
                                 in_place=in_place, keep_backup=keep_backup)
    console.print(f"Saved updated APK to [cyan]{result}[/cyan]")
    if in_place and keep_backup:
        console.print(f"Backup stored as {apk.with_name(apk.name + '.bak')}")


@app.command()
def delete(apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                      help="APK to modify"),
           member: str = typer.Argument(..., help="Member (file or directory) to remove"),
           output: Optional[Path] = typer.Option(None, "--output", "-o",
                                                 help="Location to write the patched APK"),
           in_place: bool = typer.Option(False, "--in-place", help="Overwrite the source APK"),
           keep_backup: bool = typer.Option(True, "--backup/--no-backup",
                                            help="Keep *.bak copy when patching in place")) -> None:
    """Remove a file or directory from the APK."""

    editor = _editor(apk)
    result = editor.delete_file(member, output_path=output,
                                in_place=in_place, keep_backup=keep_backup)
    console.print(f"Saved updated APK to [cyan]{result}[/cyan]")


@app.command()
def add(apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                   help="APK to modify"),
        payload: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                       help="File on disk to insert"),
        archive_path: str = typer.Argument(..., help="Target path inside the APK"),
        output: Optional[Path] = typer.Option(None, "--output", "-o",
                                              help="Location to write the patched APK"),
        in_place: bool = typer.Option(False, "--in-place", help="Overwrite the source APK"),
        keep_backup: bool = typer.Option(True, "--backup/--no-backup",
                                         help="Keep *.bak copy when patching in place")) -> None:
    """Add a brand new file into the APK."""

    editor = _editor(apk)
    result = editor.add_file(payload, archive_path, output_path=output,
                             in_place=in_place, keep_backup=keep_backup)
    console.print(f"Saved updated APK to [cyan]{result}[/cyan]")


@app.command()
def manifest(apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                        help="APK to read"),
             output: Optional[Path] = typer.Option(None, "--output", "-o",
                                                   help="Write the manifest to this file"),
             raw: bool = typer.Option(False, "--raw", help="Do not pretty-print the XML")) -> None:
    """Show or dump the decoded AndroidManifest.xml."""

    editor = _editor(apk)
    xml = editor.manifest_xml()
    if not raw:
        try:
            from xml.dom import minidom
            xml = minidom.parseString(xml).toprettyxml(indent="  ")
        except Exception:
            pass

    if output:
        if str(output) == "-":
            typer.echo(xml)
            return
        output_path = output.expanduser()
        output_path.write_text(xml, encoding="utf-8")
        console.print(f"Manifest saved to [cyan]{output_path}[/cyan]")
        return

    console.print(Syntax(xml, "xml", theme="ansi_dark", word_wrap=True))


@app.command()
def repack(source: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True,
                                         help="Directory that represents an unpacked APK"),
           output: Path = typer.Argument(..., help="Filename for the rebuilt APK")) -> None:
    """Build an APK from a directory tree created via `unpack`."""

    target = APKEditor.repack_directory(source, output)
    console.print(f"Wrote archive to [cyan]{target}[/cyan]")



@app.command()
def agent(apk: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                     help="APK to modify with the AI agent"),
          instructions: Optional[str] = typer.Argument(None, help="What the agent should change"),
          api_key: Optional[str] = typer.Option(None, "--api-key",
                                               envvar="OPENROUTER_API_KEY",
                                               help="OpenRouter API key (or set OPENROUTER_API_KEY)"),
          model: str = typer.Option("kwaipilot/kat-coder-pro:free", "--model",
                                    help="OpenRouter model identifier to use"),
          temperature: float = typer.Option(0.2, "--temperature", min=0.0, max=2.0,
                                            help="Sampling temperature passed to the model"),
          max_steps: int = typer.Option(12, "--max-steps", min=1, max=40,
                                        help="Maximum LLM/agent turns"),
          output: Optional[Path] = typer.Option(None, "--output", "-o",
                                                help="Write the patched APK to this path"),
          in_place: bool = typer.Option(False, "--in-place", help="Overwrite the input APK"),
          keep_backup: bool = typer.Option(True, "--backup/--no-backup",
                                           help="Keep *.bak when patching in place"),
          workspace: Optional[Path] = typer.Option(None, "--workspace",
                                                   help="Use/create this directory for the unpacked APK"),
          keep_workspace: bool = typer.Option(False, "--keep-workspace",
                                              help="Do not delete the temporary workspace"),
          dry_run: bool = typer.Option(False, "--dry-run",
                                       help="Skip repacking even if files changed"),
          referer: Optional[str] = typer.Option(None, "--referer",
                                               help="Optional HTTP-Referer header for OpenRouter"),
          title: Optional[str] = typer.Option(None, "--title",
                                             help="Optional X-Title header for OpenRouter"),
          timeout: float = typer.Option(90.0, "--timeout", min=10.0, max=300.0,
                                        help="HTTP timeout in seconds")) -> None:
    """Let an OpenRouter-backed agent inspect and modify an APK."""

    if not instructions:
        instructions = typer.prompt("Describe the APK edits you'd like the agent to perform")
    instructions = instructions.strip()
    if not instructions:
        _fail("Instructions cannot be empty")

    apk = apk.expanduser().resolve()

    resolved_key = api_key or os.environ.get("OPENROUTER_API_KEY")
    if not resolved_key:
        _fail("Provide an OpenRouter API key via --api-key or OPENROUTER_API_KEY")
    if in_place and output:
        _fail("Cannot combine --in-place with --output")

    editor = _editor(apk)
    metadata = editor.metadata()

    workspace_dir, cleanup = _prepare_workspace(workspace, keep_workspace)
    console.print(f"Extracting [cyan]{apk}[/cyan] into [magenta]{workspace_dir}[/magenta]…")
    try:
        editor.extract_all(workspace_dir)
    except Exception:
        if cleanup:
            shutil.rmtree(workspace_dir, ignore_errors=True)
        raise

    if dry_run:
        cleanup = False

    client = OpenRouterClient(api_key=resolved_key,
                              timeout=timeout,
                              referer=referer,
                              title=title)
    agent_runner = APKAgent(workspace=workspace_dir,
                            metadata=metadata,
                            client=client,
                            model=model,
                            instructions=instructions,
                            max_steps=max_steps,
                            temperature=temperature,
                            console=console)

    try:
        result = agent_runner.run()
    except Exception as exc:
        console.print(f"[red]Agent failed:[/red] {exc}")
        if cleanup:
            shutil.rmtree(workspace_dir, ignore_errors=True)
        raise typer.Exit(code=1)

    console.print(f"[green]Agent completed in {result.steps} step(s)[/green]")
    if result.summary:
        console.print(result.summary)
    if result.changelog:
        for item in result.changelog:
            console.print(f"- {item}")

    if dry_run:
        console.print("[yellow]Dry-run enabled: no APK was rebuilt[/yellow]")
        console.print(f"Workspace preserved at [magenta]{workspace_dir}[/magenta]")
        return

    destination = _resolve_agent_output_path(apk, output, in_place)
    if not result.modified:
        console.print("[yellow]Agent did not change any files; skipping repack[/yellow]")
        if cleanup:
            shutil.rmtree(workspace_dir, ignore_errors=True)
        else:
            console.print(f"Workspace left at [magenta]{workspace_dir}[/magenta]")
        return

    console.print("Repacking modified workspace…")
    final_path = _finalize_agent_artifact(workspace_dir, apk, destination, in_place, keep_backup)
    console.print(f"Saved updated APK to [cyan]{final_path}[/cyan]")
    if in_place and keep_backup:
        console.print(f"Backup stored as [magenta]{apk.with_name(apk.name + '.bak')}[/magenta]")

    if cleanup:
        shutil.rmtree(workspace_dir, ignore_errors=True)
    else:
        console.print(f"Workspace left at [magenta]{workspace_dir}[/magenta]")


def _editor(apk: Path) -> APKEditor:
    try:
        return APKEditor(apk)
    except Exception as exc:  # pragma: no cover - CLI level guard
        _fail(str(exc))


def _metadata_to_dict(metadata: APKMetadata) -> dict:
    return {
        "package_name": metadata.package_name,
        "version_name": metadata.version_name,
        "version_code": metadata.version_code,
        "min_sdk": metadata.min_sdk,
        "target_sdk": metadata.target_sdk,
        "file_count": metadata.file_count,
        "archive_size": metadata.archive_size,
        "compressed_size": metadata.compressed_size,
        "uncompressed_size": metadata.uncompressed_size,
        "sha256": metadata.sha256,
        "certificates": [
            {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
                "sha1": cert.sha1,
                "sha256": cert.sha256,
                "not_before": cert.not_before.isoformat(),
                "not_after": cert.not_after.isoformat(),
            }
            for cert in metadata.certificates
        ],
    }


def _render_metadata(metadata: APKMetadata, apk: Path) -> None:
    table = Table(title=str(apk), box=box.SIMPLE_HEAVY)
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Package", metadata.package_name or "unknown")
    table.add_row("Version", _format_version(metadata))
    table.add_row("SDK", _format_sdk(metadata))
    table.add_row("Entries", f"{metadata.file_count}")
    table.add_row("APK Size", f"{_fmt_bytes(metadata.archive_size)} ({metadata.archive_size:,} bytes)")
    table.add_row("Uncompressed", _fmt_bytes(metadata.uncompressed_size))
    table.add_row("Compressed", _fmt_bytes(metadata.compressed_size))
    table.add_row("SHA-256", metadata.sha256)
    console.print(table)


def _render_certificates(certificates: Sequence[CertificateInfo]) -> None:
    table = Table(title="Signing certificates", box=box.SIMPLE, highlight=True)
    table.add_column("Subject")
    table.add_column("Issuer")
    table.add_column("Serial", justify="right")
    table.add_column("SHA-256", justify="right")
    table.add_column("Validity", justify="center")

    for cert in certificates:
        validity = f"{_fmt_datetime(cert.not_before)} → {_fmt_datetime(cert.not_after)}"
        table.add_row(cert.subject, cert.issuer, cert.serial_number, cert.sha256, validity)
    console.print(table)


def _format_version(metadata: APKMetadata) -> str:
    if metadata.version_name and metadata.version_code:
        return f"{metadata.version_name} (code {metadata.version_code})"
    if metadata.version_name:
        return metadata.version_name
    if metadata.version_code:
        return f"code {metadata.version_code}"
    return "unknown"


def _format_sdk(metadata: APKMetadata) -> str:
    parts = []
    if metadata.min_sdk:
        parts.append(f"min {metadata.min_sdk}")
    if metadata.target_sdk:
        parts.append(f"target {metadata.target_sdk}")
    return ', '.join(parts) if parts else "unknown"


def _fmt_bytes(num: int) -> str:
    step = 1024.0
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(num)
    for unit in units:
        if value < step or unit == units[-1]:
            return f"{value:.1f} {unit}"
        value /= step
    return f"{value:.1f} {units[-1]}"


def _compression_ratio(entry: ArchiveEntry) -> Optional[float]:
    if entry.uncompressed_size == 0:
        return None
    ratio = (entry.compressed_size / entry.uncompressed_size) * 100
    return ratio


def _fmt_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _prepare_workspace(user_path: Optional[Path], keep_workspace: bool) -> tuple[Path, bool]:
    if user_path:
        workspace = user_path.expanduser().resolve()
        if workspace.exists():
            if any(workspace.iterdir()):
                _fail("Workspace directory must be empty")
        else:
            workspace.mkdir(parents=True)
        return workspace, False

    tmp_dir = Path(tempfile.mkdtemp(prefix="apkraft-agent-"))
    return tmp_dir, not keep_workspace


def _resolve_agent_output_path(apk: Path,
                               output: Optional[Path],
                               in_place: bool) -> Path:
    if in_place:
        return apk
    if output:
        return output.expanduser().resolve()
    suffix = ''.join(apk.suffixes) or '.apk'
    return apk.with_name(f"{apk.stem}.agent{suffix}")


def _finalize_agent_artifact(workspace: Path,
                             apk: Path,
                             destination: Path,
                             in_place: bool,
                             keep_backup: bool) -> Path:
    tmp_dir = Path(tempfile.mkdtemp(prefix="apkraft-agent-build-"))
    tmp_file = tmp_dir / destination.name
    try:
        APKEditor.repack_directory(workspace, tmp_file)
        if in_place:
            if keep_backup:
                backup = apk.with_name(apk.name + ".bak")
                if backup.exists():
                    backup.unlink()
                shutil.copy2(apk, backup)
            os.replace(tmp_file, apk)
            return apk
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp_file, destination)
        return destination
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _fail(message: str) -> None:
    console.print(f"[red]Error:[/red] {message}")
    raise typer.Exit(code=1)

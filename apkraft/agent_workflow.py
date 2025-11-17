"""Shared helpers for agent workspace lifecycle management."""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

import os
import shutil
import tempfile


def prepare_workspace(user_path: Optional[Path], keep_workspace: bool) -> Tuple[Path, bool]:
    """Return a workspace directory and whether it should be cleaned up.

    If ``user_path`` is provided the directory must either be empty or not
    exist (in which case it will be created). The returned bool indicates if
    the caller is responsible for deleting the workspace after the run.
    """

    if user_path:
        workspace = user_path.expanduser().resolve()
        if workspace.exists():
            if any(workspace.iterdir()):
                raise ValueError("Workspace directory must be empty")
        else:
            workspace.mkdir(parents=True)
        return workspace, False

    tmp_dir = Path(tempfile.mkdtemp(prefix="apkraft-agent-"))
    # When keep_workspace is True we leave the temp dir behind for inspection.
    return tmp_dir, not keep_workspace


def resolve_agent_output_path(apk: Path,
                              output: Optional[Path],
                              in_place: bool) -> Path:
    """Determine where the rebuilt APK should be written."""

    if in_place:
        return apk
    if output:
        return output.expanduser().resolve()
    suffix = ''.join(apk.suffixes) or '.apk'
    return apk.with_name(f"{apk.stem}.agent{suffix}")


def finalize_agent_artifact(workspace: Path,
                            apk: Path,
                            destination: Path,
                            in_place: bool,
                            keep_backup: bool) -> Path:
    """Repack the workspace and move the artifact into the final location."""

    from .editor import APKEditor  # Local import to avoid cycles.

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

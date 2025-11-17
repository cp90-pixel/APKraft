"""APKraft package metadata."""

from importlib.metadata import version, PackageNotFoundError

try:  # pragma: no cover - simple metadata helper
    __version__ = version("apkraft")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.1.0"

__all__ = ["__version__"]

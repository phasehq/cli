"""Runtime hook to ensure importlib.metadata.version never returns None for prompt_toolkit.
This avoids prompt_toolkit failing its version regex when wheel metadata is absent
in the frozen application.
"""
import importlib.metadata as _metadata

_real_version = _metadata.version

# Package name we need to guard.
_TARGET = "prompt_toolkit"

def _safe_version(name: str, *args, **kwargs):  # type: ignore[override]
    """Return a fake version for prompt_toolkit if metadata missing."""
    try:
        return _real_version(name, *args, **kwargs)
    except _metadata.PackageNotFoundError:
        if name == _TARGET:
            return "0.0.0"
        raise

# Monkey-patch
_metadata.version = _safe_version

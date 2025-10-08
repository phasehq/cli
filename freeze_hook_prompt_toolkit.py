"""
Runtime-hook for PyInstaller:
ensure prompt_toolkit has a __version__ attribute even when
importlib.metadata cannot find the wheel metadata in the frozen bundle.
"""
import importlib
import importlib.metadata
import sys

# Ensure the module is loaded and then safely set __version__ if it's missing.
# We set a default to prevent a crash if metadata is not found.
sys.modules.setdefault(
    "prompt_toolkit",
    importlib.import_module("prompt_toolkit")
).__dict__.setdefault(
    "__version__", importlib.metadata.version("prompt_toolkit")
)

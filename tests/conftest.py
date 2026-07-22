"""Shared pytest fixtures and import shim for the exposure checker tests.

The tool ships as a standalone script under ``scripts/`` (not an installed
package), so we load it as a module by absolute path and expose it as the
``grok_exposure_check`` fixture / import target.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "grok_exposure_check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("grok_exposure_check", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["grok_exposure_check"] = module
    spec.loader.exec_module(module)
    return module


# Import once at collection time so tests can `import grok_exposure_check`.
grok = _load_module()


@pytest.fixture
def gec():
    """Return the loaded grok_exposure_check module."""
    return grok

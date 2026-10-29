"""Load one of the SAST engine's stdlib-only helper modules by path.

`secret_mask.py` and `endpoint_policy.py` are shared by the engine (which cannot
import `app`) and the app (which does not import the engine as a package), so the
app loads the file itself — the engine directory configured for scans first, the
in-repo copy otherwise — and fails loudly when neither exists: silently skipping
a security check is the failure these modules exist to prevent.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path
from types import ModuleType

from app.config import settings

_IN_REPO = Path(__file__).resolve().parents[2] / "sast_engine"
_lock = threading.Lock()
_loaded: dict[str, ModuleType] = {}


def load(name: str) -> ModuleType:
    module = _loaded.get(name)
    if module is not None:
        return module
    with _lock:
        module = _loaded.get(name) or sys.modules.get(name)
        if module is not None:
            _loaded[name] = module
            return module
        for base in (Path(settings.sast_framework_path), _IN_REPO):
            candidate = base / f"{name}.py"
            if candidate.is_file():
                spec = importlib.util.spec_from_file_location(name, candidate)
                assert spec is not None and spec.loader is not None
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                sys.modules.setdefault(name, module)
                _loaded[name] = module
                return module
    raise RuntimeError(f"{name}.py not found next to the SAST engine")

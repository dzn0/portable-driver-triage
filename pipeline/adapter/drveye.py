"""Drive DrvEye on one driver and reshape its JSON into the bundle layout.

The engine itself (PE parsing, taint, exploit-primitive classification, …)
is vendored under `vendor/drveye/`. This adapter owns only the glue:
subprocess invocation, scope-aware filtering, and bundle emission.
"""
from __future__ import annotations
import json
import os
import subprocess
import tempfile
from pathlib import Path

from .. import __version__ as PIPELINE_VERSION
from .. import config
from ..collectors import _common as C

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DRVEYE = REPO_ROOT / "vendor" / "drveye" / "DrvEye.py"
REPORTS = REPO_ROOT / "reports"


def _python() -> str:
    """The interpreter that imported us — must have DrvEye's deps installed."""
    import sys
    return sys.executable


def invoke_drveye(sys_path: Path, timeout: int = 300) -> dict:
    """Run DrvEye on `sys_path`, return the parsed JSON report."""
    if not DRVEYE.exists():
        raise RuntimeError(f"DrvEye not vendored at {DRVEYE}")
    fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="drveye_")
    os.close(fd)
    tmp = Path(tmp_path)
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        r = subprocess.run(
            [_python(), str(DRVEYE), str(sys_path),
             "--json", str(tmp), "--no-color"],
            capture_output=True, text=True, errors="replace",
            timeout=timeout, env=env,
        )
        if not tmp.exists() or tmp.stat().st_size == 0:
            raise RuntimeError(
                f"DrvEye produced no JSON (rc={r.returncode}): "
                f"{r.stderr.strip()[-800:]}"
            )
        return json.loads(tmp.read_text(encoding="utf-8"))
    finally:
        tmp.unlink(missing_ok=True)

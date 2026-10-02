"""Static-collection primitives shared by all collectors.

Design invariants:
- Downloads use HTTPS only; host allowlist is enforced per call.
- Binary magic is validated against the downloaded file's declared suffix,
  so an HTML challenge page cannot masquerade as a ZIP/EXE/MSI/CAB.
- urllib is tried first; on failure, Windows curl (IPv4, cert validation on)
  is the fallback. Certificate checking is never disabled.
- No installer or driver is ever executed; 7-Zip is used for every archive.
"""
from __future__ import annotations
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .. import config
from .. import progress

# keep subprocess silent on Windows; 0 is a no-op (and the only valid value)
# on non-Windows platforms, where passing creationflags at all is an error.
CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
UA = "Mozilla/5.0 PortableDriverTriage/0.1"
MAGIC = {
    ".exe": b"MZ",
    ".sys": b"MZ",
    ".dll": b"MZ",
    ".msi": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    ".cab": b"MSCF",
    ".zip": b"PK",
    ".7z": b"7z\xbc\xaf\x27\x1c",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def utc_now_compact() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _host_allowed(url: str, allowed_hosts: list[str]) -> None:
    host = (urlparse(url).hostname or "").lower()
    if not any(host == h or host.endswith("." + h) for h in allowed_hosts):
        raise ValueError(f"Download host outside source allowlist: {host}")


def _validate_magic(path: Path) -> None:
    expected = MAGIC.get(path.suffix.lower())
    if not expected:
        return
    with path.open("rb") as f:
        header = f.read(len(expected))
    if not header.startswith(expected):
        raise ValueError(
            f"Response is not a valid {path.suffix} (got {header!r}; "
            f"likely an HTML anti-bot challenge)"
        )


def fetch_text(url: str, allowed_hosts: list[str], timeout: int = 60) -> str:
    _host_allowed(url, allowed_hosts)
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=timeout) as r:
        _host_allowed(r.geturl(), allowed_hosts)
        return r.read(32 << 20).decode("utf-8", errors="replace")


def download(
    url: str,
    target: Path,
    allowed_hosts: list[str],
    max_mb: int = 1500,
    timeout: int = 90,
) -> dict:
    """Download `url` to `target`. Returns a provenance dict."""
    if urlparse(url).scheme != "https":
        raise ValueError("HTTPS required")
    _host_allowed(url, allowed_hosts)
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")

    fname = Path(urlparse(url).path).name or "download"
    try:
        req = Request(url, headers={"User-Agent": UA})
        with urlopen(req, timeout=timeout) as r:
            _host_allowed(r.geturl(), allowed_hosts)
            final_url = r.geturl()
            clen = (r.headers.get("Content-Length") or "").strip()
            total_mb = int(clen) / (1 << 20) if clen.isdigit() else None
            written = 0
            last = 0.0
            with partial.open("wb") as f:
                while chunk := r.read(1 << 20):
                    written += len(chunk)
                    if written > max_mb * (1 << 20):
                        raise ValueError("Download exceeds size limit")
                    f.write(chunk)
                    now = time.monotonic()
                    if now - last > 0.2:
                        mb = written / (1 << 20)
                        bar = f"{mb:.0f}/{total_mb:.0f} MB" if total_mb else f"{mb:.0f} MB"
                        progress.report(f"downloading {fname} · {bar}")
                        last = now
        _validate_magic(partial)
        partial.replace(target)
    except Exception as exc:
        partial.unlink(missing_ok=True)
        progress.report(f"downloading {fname} · curl fallback")
        curl = shutil.which("curl.exe") or shutil.which("curl")
        if not curl:
            raise RuntimeError(f"urllib: {exc}; curl not found on PATH") from exc
        cmd = [
            curl, "--ipv4", "--location", "--fail", "--silent", "--show-error",
            "--proto", "=https", "--proto-redir", "=https",
            "--connect-timeout", "20",
            "--max-time", str(max(90, timeout * 3)),
            "--max-filesize", str(max_mb * (1 << 20)),
            "--user-agent", UA,
            "--output", str(partial),
            "--write-out", "%{url_effective}",
            url,
        ]
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=max(100, timeout * 3 + 10), creationflags=CREATE_NO_WINDOW,
        )
        if r.returncode:
            raise RuntimeError(f"urllib: {exc}; curl: {r.stderr.strip()}") from exc
        final_url = r.stdout.strip()
        _host_allowed(final_url, allowed_hosts)
        if partial.stat().st_size > max_mb * (1 << 20):
            raise ValueError("Download exceeds size limit")
        _validate_magic(partial)
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)

    return {
        "url": url,
        "final_url": final_url,
        "path": str(target),
        "size": target.stat().st_size,
        "sha256": sha256_file(target),
        "downloaded_at": utc_now(),
    }


def extract(package: Path, destination: Path, timeout: int = 240) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    progress.report(f"extracting {package.name}")
    r = subprocess.run(
        [str(config.sevenzip()), "x", str(package), "-o" + str(destination), "-y", "-bd"],
        capture_output=True, text=True, errors="replace",
        timeout=timeout, creationflags=CREATE_NO_WINDOW,
    )
    return {
        "package": str(package),
        "destination": str(destination),
        "exit_code": r.returncode,
        "output_tail": (r.stdout + r.stderr)[-8000:],
    }


def extract_pe_resources(package: Path, destination: Path, timeout: int = 180) -> dict:
    """Extract an app EXE's PE *resources* with 7-Zip's `-tPE` view.

    Some monitoring utilities (CPU-Z, HWMonitor, HWiNFO) ship their kernel driver
    embedded as a whole-PE resource inside the application binary. Plain `7z x`
    auto-unpacks the EXE and does not preserve that resource intact; forcing the
    PE view with `-tPE` does. Pair with `collect_sys_files(include_native_pe=True)`
    to recover the driver by content."""
    destination.mkdir(parents=True, exist_ok=True)
    progress.report(f"extracting PE resources {package.name}")
    r = subprocess.run(
        [str(config.sevenzip()), "x", "-tPE", str(package),
         "-o" + str(destination), "-y", "-bd"],
        capture_output=True, text=True, errors="replace",
        timeout=timeout, creationflags=CREATE_NO_WINDOW,
    )
    return {"package": str(package), "destination": str(destination),
            "method": "7z -tPE", "exit_code": r.returncode,
            "output_tail": (r.stdout + r.stderr)[-8000:]}


_NESTED_ARCHIVE_EXT = {".exe", ".msi", ".cab", ".zip", ".7z", ".msu"}


def extract_nested(root: Path, timeout: int = 300) -> list[dict]:
    """Extract every nested archive/installer found under `root` one level down.

    Used for installers wrapped in another installer (e.g. an NSIS setup `.exe`
    inside a distribution `.zip`). Each candidate is extracted into a sibling
    `<name>.unpacked/`; files 7-Zip cannot open as archives fail harmlessly.
    Returns per-extraction records. Call after the first pass if it found no
    drivers, to keep the common (single-stage) case noise-free."""
    results: list[dict] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in _NESTED_ARCHIVE_EXT:
            continue
        out = p.with_suffix(p.suffix + ".unpacked")
        if out.exists():
            continue
        try:
            results.append(extract(p, out, timeout))
        except Exception as e:
            results.append({"package": str(p), "error": str(e)})
    return results


def pe_identity(path: Path) -> dict | None:
    """Return machine/subsystem of a PE, or None if not a PE."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
        if head[:2] != b"MZ":
            return None
        off = struct.unpack_from("<I", head, 0x3C)[0]
        if off + 96 > len(head):
            with open(path, "rb") as f:
                f.seek(off)
                head = f.read(256)
            off = 0
        if head[off:off + 4] != b"PE\0\0":
            return None
        machine = struct.unpack_from("<H", head, off + 4)[0]
        subsystem = struct.unpack_from("<H", head, off + 24 + 68)[0]
        return {
            "machine": hex(machine),
            "subsystem": subsystem,
            "native": subsystem == 1,
        }
    except (OSError, struct.error):
        return None


def verify_signature(path: Path) -> dict:
    """Run signtool /kp if available. Never fails the overall collection."""
    tool = config.signtool()
    if not tool:
        return {"accepted": None, "reason": "signtool not installed"}
    try:
        r = subprocess.run(
            [str(tool), "verify", "/kp", "/v", str(path)],
            capture_output=True, text=True, errors="replace",
            timeout=60, creationflags=CREATE_NO_WINDOW,
        )
        return {
            "accepted": r.returncode == 0,
            "exit_code": r.returncode,
            "output_tail": (r.stdout + r.stderr)[-4000:],
        }
    except Exception as e:
        return {"accepted": None, "error": str(e)}


def collect_sys_files(
    extracted_root: Path,
    drivers_dir: Path,
    *,
    verify: bool = True,
    include_native_pe: bool = False,
) -> list[dict]:
    """Walk `extracted_root`, find driver binaries, dedup by sha256, and copy
    survivors to `drivers_dir/<sha256>.sys`. Returns per-driver records.

    By default only `*.sys` files are collected. With `include_native_pe=True`,
    any file whose *content* is a native-subsystem PE (IMAGE_SUBSYSTEM_NATIVE)
    is collected too, regardless of extension — this recovers drivers that an
    MSI (`fil<hex>` stream names) or a PE-resource extraction (`107`, `725`)
    leaves without a `.sys` suffix, cross-platform and without Windows-only MSI
    APIs. The native-subsystem test naturally excludes user-mode DLLs/EXEs."""
    candidates = [p for p in extracted_root.rglob("*")
                  if p.is_file() and p.suffix.lower() == ".sys"]
    if include_native_pe:
        seen_paths = {p.resolve() for p in candidates}
        for p in extracted_root.rglob("*"):
            if not p.is_file() or p.resolve() in seen_paths:
                continue
            ident = pe_identity(p)
            if ident and ident.get("native"):
                candidates.append(p)
    files = sorted(candidates)
    progress.report(f"scanning {len(files)} candidate(s) for drivers")
    rows: list[dict] = []
    seen: set[str] = set()
    for p in files:
        progress.report(f"hashing {p.name}")
        digest = sha256_file(p)
        if digest in seen:
            continue
        seen.add(digest)
        ident = pe_identity(p)
        signature = verify_signature(p) if verify else {"accepted": None, "reason": "skipped"}
        target = drivers_dir / f"{digest}.sys"
        if not target.exists():
            shutil.copy2(p, target)
        rows.append({
            "sha256": digest,
            "original_name": p.name,
            "size": p.stat().st_size,
            "pe": ident,
            "signature": signature,
            "extraction_path": str(p.relative_to(extracted_root)),
            "stored_path": str(target),
        })
    return rows

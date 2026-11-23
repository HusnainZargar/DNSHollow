"""Builds the agent download (tar.gz) from the agent/ folder.
The archive is deterministic, so its SHA-256 only changes when the code changes."""
from __future__ import annotations

import gzip
import hashlib
import io
import os
import tarfile
from pathlib import Path
from typing import Tuple

PKG = "dnshollow_agent"


def agent_root() -> Path:
    env = os.environ.get("DNSHOLLOW_AGENT_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[1] / "agent"


def _files(root: Path):
    return sorted(p for p in (root / PKG).rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc")


def build(root: Path | None = None) -> Tuple[bytes, str]:
    root = root or agent_root()
    files = _files(root)
    if not files:
        raise FileNotFoundError("agent code not found in %s" % root)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for f in files:
            data = f.read_bytes()
            info = tarfile.TarInfo(str(f.relative_to(root)))
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
        g.write(raw.getvalue())
    blob = gz.getvalue()
    return blob, hashlib.sha256(blob).hexdigest()


class BundleCache:
    """Rebuilds only if an agent file changed."""

    def __init__(self):
        self._sig = None
        self._val = None

    def get(self) -> Tuple[bytes, str]:
        root = agent_root()
        sig = tuple((str(f), f.stat().st_mtime_ns, f.stat().st_size) for f in _files(root))
        if sig != self._sig:
            self._val, self._sig = build(root), sig
        return self._val

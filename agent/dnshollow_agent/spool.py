"""Disk spool: batches that could not be sent wait here (oldest first)."""
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("dnshollow.spool")


class Spool:
    def __init__(self, directory, max_bytes: int = 50 * 1024 * 1024):
        self.dir = Path(directory)
        self.max_bytes = max_bytes
        self.dropped = 0
        self.dir.mkdir(parents=True, exist_ok=True)

    def _files(self):
        return sorted(self.dir.glob("*.json"))

    def count(self) -> int:
        return len(self._files())

    def save(self, batch: dict) -> None:
        name = "%020d-%s.json" % (time.time_ns(), batch["batch_id"])
        tmp = self.dir / (name + ".tmp")
        tmp.write_text(json.dumps(batch))
        os.replace(tmp, self.dir / name)
        self._enforce_cap()

    def _enforce_cap(self) -> None:
        files = self._files()
        total = sum(f.stat().st_size for f in files)
        while total > self.max_bytes and files:
            victim = files.pop(0)                  # oldest data is dropped first
            total -= victim.stat().st_size
            victim.unlink(missing_ok=True)
            self.dropped += 1
            log.warning("spool full: dropped oldest batch %s", victim.name)

    def oldest(self) -> Optional[Path]:
        files = self._files()
        return files[0] if files else None

    @staticmethod
    def load(path: Path) -> Optional[dict]:
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            path.unlink(missing_ok=True)           # unreadable file: discard
            return None

    @staticmethod
    def delete(path: Path) -> None:
        path.unlink(missing_ok=True)

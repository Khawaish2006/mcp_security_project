"""Structured audit log: one JSON line per gateway decision.

Logs hashes, scores, the action and its reason, plus a short preview of the
added text. Long token-like strings (keys, base64 blobs) are redacted so the
log never stores secrets copied from a descriptor.
"""

import json
import re
import time
from pathlib import Path

_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
PREVIEW_CHARS = 200


def redact(text: str) -> str:
    return _TOKEN.sub("<redacted>", text or "")[:PREVIEW_CHARS]


class AuditLog:
    def __init__(self, path: Path | None = None):
        self.path = path
        self.entries: list[dict] = []

    def log(self, **event) -> dict:
        entry = {"ts": round(time.time(), 3), **event}
        if "added_text" in entry:
            entry["added_text"] = redact(entry["added_text"])
        self.entries.append(entry)
        if self.path:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except OSError as e:
                # A logging failure must not silently allow anything; record it in memory.
                entry["log_write_error"] = str(e)
        return entry

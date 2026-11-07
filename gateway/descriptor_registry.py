"""Approved-descriptor registry.

For each tool it keeps:
    original   d0, the first approved descriptor (for cumulative drift)
    approved   the last approved descriptor (the current trusted baseline)
    status     active | quarantined | blocked
    pending    a changed descriptor waiting for human review
    n_updates  approved updates since d0
    max_step_risk  highest per-update risk seen so far

Only the methods below change trusted state; a hash mismatch alone never
does. Optionally persisted as JSON so the gateway remembers across restarts.
"""

import json
import time
from pathlib import Path

from gateway.canonical import descriptor_hash


class DescriptorRegistry:
    def __init__(self, path: Path | None = None):
        self.path = path
        self.tools: dict[str, dict] = {}
        if path and path.exists():
            self.tools = json.loads(path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.tools, indent=2, ensure_ascii=False), encoding="utf-8")

    def get(self, name: str) -> dict | None:
        return self.tools.get(name)

    def compare(self, descriptor: dict) -> str:
        """'new', 'unchanged' (same as approved) or 'changed'."""
        rec = self.tools.get(descriptor["name"])
        if rec is None:
            return "new"
        return "unchanged" if descriptor_hash(descriptor) == rec["approved_hash"] else "changed"

    def approve_initial(self, descriptor: dict) -> None:
        h = descriptor_hash(descriptor)
        self.tools[descriptor["name"]] = {
            "original": descriptor, "approved": descriptor, "approved_hash": h, "status": "active",
            "pending": None, "n_updates": 0, "max_step_risk": None,
            "history": [{"hash": h, "action": "REGISTERED", "ts": time.time()}],
        }
        self._save()

    def record(self, descriptor: dict, action: str, r_step: float | None) -> None:
        """Apply a gateway decision about a changed descriptor."""
        rec = self.tools[descriptor["name"]]
        h = descriptor_hash(descriptor)
        if r_step is not None:
            rec["max_step_risk"] = r_step if rec["max_step_risk"] is None else max(rec["max_step_risk"], r_step)
        if action == "ALLOW":
            rec.update(approved=descriptor, approved_hash=h, status="active", pending=None)
            rec["n_updates"] += 1
        elif action == "QUARANTINE":
            rec.update(status="quarantined", pending=descriptor)
        elif action == "BLOCK":
            rec.update(status="blocked", pending=None)
        rec["history"].append({"hash": h, "action": action, "ts": time.time()})
        self._save()

    def resolve_review(self, name: str, approve: bool) -> None:
        """Human reviewer decision on a quarantined descriptor."""
        rec = self.tools[name]
        if rec["status"] != "quarantined" or rec["pending"] is None:
            raise ValueError(f"{name} has no pending review")
        if approve:
            self.record(rec["pending"], "ALLOW", None)
        else:
            self.record(rec["pending"], "BLOCK", None)

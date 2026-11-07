"""The gateway: sits between an MCP client and an upstream MCP server.

On every tools/list from the upstream server it checks each descriptor:
    new tool        -> registered as the approved original (trust on first use)
    unchanged       -> exposed as approved
    changed         -> hard rules, then detector (r_step, r_cum), then policy:
                       ALLOW makes it the new baseline; QUARANTINE hides the tool
                       until a reviewer decides; BLOCK hides it permanently.
On every tools/call it only forwards calls to active tools whose live
descriptor still matches the approved one.

The detector failing never lets a change through (hard rule -> QUARANTINE).
"""

import time

from gateway.audit_log import AuditLog
from gateway.canonical import descriptor_hash
from gateway.descriptor_registry import DescriptorRegistry
from gateway.diff import added_text
from gateway.features import security_flags
from gateway.policy_engine import Observation, apply_hard_rules


class Gateway:
    def __init__(self, detector, policy, registry: DescriptorRegistry | None = None, audit: AuditLog | None = None):
        self.detector = detector
        self.policy = policy
        self.registry = registry or DescriptorRegistry()
        self.audit = audit or AuditLog()
        self._live_hash: dict[str, str] = {}

    def review_tools(self, descriptors: list[dict]) -> list[dict]:
        """Filter an upstream tools/list result. Returns the descriptors the client may see."""
        exposed = []
        for desc in descriptors:
            name = desc["name"]
            self._live_hash[name] = descriptor_hash(desc)
            status = self.registry.compare(desc)
            if status == "new":
                self.registry.approve_initial(desc)
                self.audit.log(tool=name, event="registered", new_hash=self._live_hash[name], action="ALLOW",
                               reason="first seen; approved as original")
            elif status == "changed" and self.registry.get(name)["status"] != "blocked":
                pending = self.registry.get(name)["pending"]
                if not (pending and descriptor_hash(pending) == self._live_hash[name]):
                    self._evaluate_change(desc)
            rec = self.registry.get(name)
            if rec["status"] == "active" and rec["approved_hash"] == self._live_hash[name]:
                exposed.append(desc)
        return exposed

    def _evaluate_change(self, desc: dict) -> dict:
        name = desc["name"]
        rec = self.registry.get(name)
        d0, prev, new = rec["original"]["description"], rec["approved"]["description"], desc.get("description", "")
        old_hash = rec["approved_hash"]
        start = time.perf_counter()
        added = added_text(prev, new)
        flags = [k for k, v in security_flags(added, name).items() if v]
        r_step = r_cum = None
        detector_ok = True
        try:
            r_step, r_cum = self.detector.score(d0, prev, new, name)
        except Exception as e:  # noqa: BLE001 - any detector failure must fail closed
            detector_ok = False
            flags.append(f"detector_error:{type(e).__name__}")
        decision = apply_hard_rules(flags, detector_ok)
        if decision is None:
            obs = Observation(r_step, r_cum, rec["n_updates"] + 1, rec["max_step_risk"])
            decision = self.policy.decide(obs)
        action, reason = decision
        self.registry.record(desc, action, r_step)
        return self.audit.log(
            tool=name, event="descriptor_changed", old_hash=old_hash,
            new_hash=descriptor_hash(desc), r_step=r_step, r_cum=r_cum, flags=flags, action=action, reason=reason,
            added_text=added, policy=getattr(self.policy, "name", "?"),
            latency_ms=round(1000 * (time.perf_counter() - start), 1))

    def authorize_call(self, name: str) -> tuple[bool, str]:
        rec = self.registry.get(name)
        if rec is None:
            return False, "unknown tool"
        if rec["status"] != "active":
            return False, f"tool is {rec['status']}"
        if self._live_hash.get(name) != rec["approved_hash"]:
            return False, "live descriptor differs from the approved one; re-list tools first"
        return True, "approved"

    def call(self, name: str, arguments: dict, upstream_call) -> dict:
        ok, reason = self.authorize_call(name)
        self.audit.log(tool=name, event="tool_call", action="ALLOW" if ok else "BLOCK", reason=reason)
        if not ok:
            return {"isError": True, "content": [{"type": "text", "text": f"Blocked by MCP security gateway: {reason}"}]}
        return upstream_call(name, arguments)

    def resolve_review(self, name: str, approve: bool) -> None:
        self.registry.resolve_review(name, approve)
        self.audit.log(tool=name, event="review", action="ALLOW" if approve else "BLOCK",
                       reason="human reviewer " + ("approved" if approve else "rejected"))

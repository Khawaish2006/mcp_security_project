"""End-to-end demo: scripted MCP description updates through the gateway.

For each scenario the mock server advertises version 0, 1, 2, ... of its
tools; the gateway decides on every change. A simulated human reviewer
resolves quarantines (approves the legitimate scenarios, rejects the attack
scenarios), so each policy's real outcome and reviewer workload are visible.
Writes logs/audit_<policy>.jsonl.

Requires the trained detector and MDP (python -m experiments.run_eval).
Usage (from the mcp-security folder):  python -m experiments.demo
"""

import json
import sys
from pathlib import Path

import numpy as np

from gateway.audit_log import AuditLog
from gateway.descriptor_registry import DescriptorRegistry
from gateway.detector import DualDetector
from gateway.embedder import SentenceEmbedder
from gateway.interceptor import Gateway
from gateway.policy_engine import MDPPolicy, Threshold
from mdp.model import StateSpace
from server.scenarios import SCENARIOS, call_tool, descriptors, n_steps

ROOT = Path(__file__).resolve().parent.parent
LEGITIMATE = {"benign_updates", "security_note_hard_negative"}
ARGS = {"simple_division": {"a": 6, "b": 3}, "calculate_total": {"price": 2.5, "quantity": 4},
        "search_products": {"query": "lamp"}, "get_weather": {"city": "Delhi"}}


def load_policies() -> dict:
    results = json.loads((ROOT / "results" / "results.json").read_text(encoding="utf-8"))
    tuned = results["policies"]["tuned"]
    mdp = json.loads((ROOT / "models" / "mdp_policy.json").read_text(encoding="utf-8"))
    space = StateSpace(tuple(mdp["risk_bins"]), mdp["max_count"])
    return {"threshold": Threshold(*tuned["threshold"]),
            "cumulative_threshold": Threshold(*tuned["cumulative_threshold"], key="r_max", name="cumulative_threshold"),
            "mdp": MDPPolicy(space, np.array(mdp["table"]))}


def run_scenario(name: str, detector, policy, log_path: Path) -> list[dict]:
    gw = Gateway(detector, policy, DescriptorRegistry(), AuditLog(log_path))
    rows = []
    for step in range(n_steps(name)):
        before = len(gw.audit.entries)
        gw.review_tools(descriptors(name, step))
        for e in gw.audit.entries[before:]:
            if e["event"] == "descriptor_changed":
                rows.append({"step": step, "tool": e["tool"], "r_step": e["r_step"], "r_cum": e["r_cum"],
                             "action": e["action"], "reason": e["reason"], "added": e["added_text"]})
        for tool, rec in gw.registry.tools.items():
            if rec["status"] == "quarantined":
                approve = name in LEGITIMATE
                gw.resolve_review(tool, approve)
                rows.append({"step": "review", "tool": tool, "action": "approved" if approve else "rejected"})
    tool = next(iter(SCENARIOS[name]))
    result = gw.call(tool, ARGS[tool], call_tool)
    rows.append({"step": "call", "tool": tool, "action": "BLOCK" if result["isError"] else "ALLOW",
                 "reason": result["content"][0]["text"]})
    return rows


def fmt(x):
    return "  -  " if x is None else f"{x:.2f}"


def printable(text: str) -> str:
    """Show hidden characters as \\uXXXX instead of printing them."""
    return text.encode("ascii", "backslashreplace").decode("ascii")


def main() -> int:
    emb = SentenceEmbedder(ROOT / "data" / "cache" / "embeddings.npz")
    detector = DualDetector.load(ROOT / "models" / "detector.joblib", emb)
    policies = load_policies()
    logs = ROOT / "logs"
    logs.mkdir(exist_ok=True)
    for f in logs.glob("audit_*.jsonl"):
        f.unlink()
    for scenario in SCENARIOS:
        kind = "legitimate" if scenario in LEGITIMATE else "attack"
        print(f"\n=== {scenario} ({kind}) ===")
        for pname, policy in policies.items():
            print(f"--- policy: {pname}")
            for r in run_scenario(scenario, detector, policy, logs / f"audit_{pname}.jsonl"):
                if r["step"] == "call":
                    print(f"  tool call {r['tool']}: {r['action']} ({printable(r['reason'])})")
                elif r["step"] == "review":
                    print(f"     reviewer {r['action']} the quarantined update")
                else:
                    print(f"  v{r['step']} r_step={fmt(r['r_step'])} r_cum={fmt(r['r_cum'])} -> {r['action']:<10}"
                          f" + \"{printable(r['added'])[:70]}\"")
    emb.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())

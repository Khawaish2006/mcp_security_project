"""Train/val/test splits grouped by MCP server.

Everything from one server (its clean tools, benign edits and the attacks
on it) lands in exactly one split, so the test set contains servers the
detector has never seen. This prevents near-duplicate leakage between
train and test.

Also provides a leave-one-paradigm-out split: every attack of one MCPTox
paradigm goes to test, to measure generalization to an unseen attack style.
"""

import random

RATIOS = {"train": 0.70, "val": 0.15, "test": 0.15}


def assign_splits(sequences: list[dict], seed: int) -> None:
    """Set seq["split"] in place, balancing the number of sequences per split."""
    sizes: dict[str, int] = {}
    for s in sequences:
        sizes[s["server"]] = sizes.get(s["server"], 0) + 1
    servers = sorted(sizes)
    random.Random(seed).shuffle(servers)
    # Largest servers first so the greedy fill ends near the target ratios.
    servers.sort(key=lambda srv: -sizes[srv])
    total = sum(sizes.values())
    filled = {name: 0 for name in RATIOS}
    server_split = {}
    for srv in servers:
        name = max(RATIOS, key=lambda n: RATIOS[n] * total - filled[n])
        server_split[srv] = name
        filled[name] += sizes[srv]
    for s in sequences:
        s["split"] = server_split[s["server"]]


def leave_one_paradigm_out(sequences: list[dict], paradigm: str) -> dict[str, list[dict]]:
    """Attacks of `paradigm` are test-only; other attacks train. Benign keeps its server split."""
    out = {"train": [], "test": []}
    for s in sequences:
        if s["seq_label"] == 1:
            out["test" if s["paradigm"] == paradigm else "train"].append(s)
        else:
            out["test" if s["split"] == "test" else "train"].append(s)
    return out


def leak_check(sequences: list[dict]) -> None:
    """Raise if a server, tool or MCPTox source record appears in more than one split."""
    for key in ("server", "tool_id", "source_id"):
        seen: dict[str, str] = {}
        for s in sequences:
            value = s.get(key)
            if value is None:
                continue
            if seen.setdefault(value, s["split"]) != s["split"]:
                raise ValueError(f"leak: {key}={value!r} in {seen[value]} and {s['split']}")

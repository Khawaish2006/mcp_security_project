"""Build RugPullBench: sequences of tool-description versions.

Every sequence starts from an approved clean description d0 and applies
T updates. Sequence types:

    benign           1-5 legitimate edits
    one_shot         the full poison in a single update (classic rug pull)
    slow_split       the poison's own sentences spread over 2-4 updates
    slow_decomposed  the attack rebuilt as framing/tool/target/action parts
    mixed            1-2 legitimate edits, then a one-shot or slow attack

Every update inside an attack is labelled step_label=1; payload_complete
marks the update after which the attack is fully in place.

Outputs (from the mcp-security folder: python -m benchmark.make_sequences):
    data/sequences.jsonl     one row per sequence (all versions)
    data/versions.jsonl      one row per update (the detector's training unit)
    data/benchmark_stats.json
"""

import json
import random
import sys
from collections import Counter
from pathlib import Path

from benchmark.benign_edits import random_edit
from benchmark.slow_attacks import decompose_fragments, extract_components, split_fragments
from benchmark.soften import soften
from benchmark.splits import assign_splits, leak_check
from gateway.diff import added_text

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
SEED = 42

BENIGN_PER_OFFICIAL_TOOL = 3
BENIGN_PER_MCPTOX_PREFIX = 2
ATTACK_TYPES = ["one_shot", "slow_split", "slow_decomposed", "mixed"]
BUNDLE_PROB = 0.3


def _append(description: str, fragment: str) -> str:
    description = description.rstrip()
    if description and not description.endswith((".", "!", "?")):
        description += "."
    return f"{description} {fragment}".strip()


def load_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def load_bases() -> tuple[list[dict], list[dict]]:
    """Return (clean bases, MCPTox records). A base is a clean d0 with its origin."""
    official = load_jsonl(DATA / "clean_tools.jsonl")
    mcptox = load_jsonl(DATA / "mcptox_malicious.jsonl")
    bases = [{"tool_id": t["tool_id"], "server": t["server"], "tool_name": t["tool_name"],
              "d0": t["description"], "base_source": "official", "hard_negative": t["hard_negative"]}
             for t in official]
    for r in mcptox:
        if r["clean_prefix"]:
            bases.append({"tool_id": f"mcptox:{r['source_id']}", "server": r["server"],
                          "tool_name": r["tool_name"], "d0": r["clean_prefix"],
                          "base_source": "mcptox_t1", "hard_negative": False})
    return bases, mcptox


def _benign_steps(description: str, n: int, rng: random.Random, siblings: list[str] | None = None) -> list[dict]:
    """n legitimate updates. About 30% are releases that bundle 2-3 edits at once, so the
    size of a change alone does not separate benign updates from multi-sentence attacks."""
    steps = []
    for _ in range(n):
        n_edits = rng.choice((2, 3)) if rng.random() < BUNDLE_PROB else 1
        types, ids = [], []
        for _ in range(n_edits):
            description, change_type, template_id = random_edit(description, rng, siblings)
            types.append(change_type)
            ids.append(template_id)
        steps.append({"description": description, "change_type": types[0] if n_edits == 1 else "bundle",
                      "template_id": ids[0] if n_edits == 1 else "bundle:" + "+".join(ids),
                      "step_label": 0, "payload_complete": False})
    return steps


def _attack_steps(start: str, fragments: list[str], change_type: str, template_ids: list[str]) -> list[dict]:
    steps, description = [], start
    for i, fragment in enumerate(fragments):
        description = _append(description, fragment)
        steps.append({"description": description, "change_type": change_type, "template_id": template_ids[i],
                      "step_label": 1, "payload_complete": i == len(fragments) - 1})
    return steps


def build_attack(record: dict, base: dict, rng: random.Random) -> dict:
    payload = record["poison"] if record["paradigm"] == "Template-1" and record["clean_prefix"] else record["text"]
    softened = rng.random() < 0.5
    if softened:
        payload = soften(payload)
    seq_type = rng.choice(ATTACK_TYPES)
    steps = []
    attack_type = seq_type
    if seq_type == "mixed":
        steps = _benign_steps(base["d0"], rng.randint(1, 2), rng, base.get("siblings"))
        attack_type = rng.choice(["one_shot", "slow_split", "slow_decomposed"])
    start = steps[-1]["description"] if steps else base["d0"]
    style = "softened" if softened else "original"

    fragments = None
    if attack_type == "slow_decomposed":
        result = decompose_fragments(payload, rng, record["tool_name"])
        if result:
            fragments, template_ids = result
            style = "templated"
        else:
            attack_type = "slow_split"
    if attack_type == "slow_split":
        fragments = split_fragments(payload, rng.randint(2, 4), record["tool_name"])
        template_ids = [f"mcptox_split:{i}" for i in range(len(fragments))]
        if len(fragments) < 2:
            attack_type = "one_shot"
    if attack_type == "one_shot":
        fragments, template_ids = [payload], ["mcptox_full"]
    if seq_type != "mixed":
        seq_type = attack_type

    steps += _attack_steps(start, fragments, f"malicious_{attack_type}", template_ids)
    return {"seq_type": seq_type, "attack_type": attack_type, "seq_label": 1, "style": style,
            "source_id": record["source_id"], "paradigm": record["paradigm"], "risk": record["risk"],
            "steps": steps}


def build_sequences(seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    bases, mcptox = load_bases()
    # Sibling tools per server: official tool names plus the real tools attacks on that
    # server reference, so benign edits can mention the same tools attackers abuse.
    tools_by_server: dict[str, set[str]] = {}
    for b in bases:
        if b["base_source"] == "official":
            tools_by_server.setdefault(b["server"], set()).add(b["tool_name"])
    for r in mcptox:
        tools_by_server.setdefault(r["server"], set()).update(extract_components(r["text"], r["tool_name"])[0])
    for b in bases:
        b["siblings"] = sorted(tools_by_server.get(b["server"], set()) - {b["tool_name"]})
    by_server: dict[tuple[str, str], list[dict]] = {}
    for b in bases:
        by_server.setdefault((b["base_source"], b["server"]), []).append(b)
    prefix_base = {b["tool_id"]: b for b in bases if b["base_source"] == "mcptox_t1"}
    all_official = [b for b in bases if b["base_source"] == "official"]

    def base_for(record: dict) -> dict:
        own = prefix_base.get(f"mcptox:{record['source_id']}")
        if own:
            return own
        # Prefer a clean tool of the same server, so the poison targets a real neighbour.
        pool = by_server.get(("official", record["server"])) or by_server.get(("mcptox_t1", record["server"]))
        if pool:
            return rng.choice(pool)
        # Last resort: borrow a description under a new id owned by this server.
        borrowed = rng.choice(all_official)
        return dict(borrowed, server=record["server"], base_source="borrowed",
                    tool_id=f"{record['server']}/borrowed:{borrowed['tool_id']}")

    sequences = []
    for base in bases:
        n = BENIGN_PER_OFFICIAL_TOOL if base["base_source"] == "official" else BENIGN_PER_MCPTOX_PREFIX
        for _ in range(n):
            sequences.append({"base": base, "seq_type": "benign", "attack_type": None, "seq_label": 0,
                              "style": None, "source_id": None, "paradigm": None, "risk": None,
                              "steps": _benign_steps(base["d0"], rng.randint(1, 5), rng, base["siblings"])})

    for record in mcptox:
        base = base_for(record)
        seq = build_attack(record, base, rng)
        seq["base"] = base
        sequences.append(seq)

    rng.shuffle(sequences)
    for i, seq in enumerate(sequences):
        base = seq.pop("base")
        seq.update({"seq_id": f"seq_{i:05d}", "tool_id": base["tool_id"], "server": base["server"],
                    "tool_name": base["tool_name"], "base_source": base["base_source"],
                    "hard_negative": base["hard_negative"], "d0": base["d0"]})
    assign_splits(sequences, seed)
    return sequences


def flatten(sequences: list[dict]) -> list[dict]:
    """One row per update: (d0, prev, new) plus labels and metadata."""
    rows = []
    for seq in sequences:
        prev = seq["d0"]
        for k, step in enumerate(seq["steps"], start=1):
            rows.append({
                "seq_id": seq["seq_id"], "step": k, "n_steps": len(seq["steps"]),
                "tool_id": seq["tool_id"], "server": seq["server"], "tool_name": seq["tool_name"],
                "d0": seq["d0"], "prev": prev, "new": step["description"],
                "added_text": added_text(prev, step["description"]),
                "change_type": step["change_type"], "template_id": step["template_id"],
                "step_label": step["step_label"], "payload_complete": step["payload_complete"],
                "seq_type": seq["seq_type"], "seq_label": seq["seq_label"], "style": seq["style"],
                "paradigm": seq["paradigm"], "risk": seq["risk"], "source_id": seq["source_id"],
                "base_source": seq["base_source"], "hard_negative": seq["hard_negative"], "split": seq["split"],
            })
            prev = step["description"]
    return rows


def stats(sequences: list[dict], rows: list[dict]) -> dict:
    return {
        "sequences": len(sequences),
        "updates": len(rows),
        "sequences_by_type": dict(Counter(s["seq_type"] for s in sequences)),
        "attack_style": dict(Counter(s["style"] for s in sequences if s["seq_label"])),
        "updates_by_label": dict(Counter(r["step_label"] for r in rows)),
        "updates_by_change_type": dict(Counter(r["change_type"] for r in rows)),
        "split_sequences": {sp: dict(Counter(s["seq_label"] for s in sequences if s["split"] == sp))
                            for sp in ("train", "val", "test")},
        "split_servers": {sp: len({s["server"] for s in sequences if s["split"] == sp}) for sp in ("train", "val", "test")},
        "steps_per_sequence": dict(sorted(Counter(len(s["steps"]) for s in sequences).items())),
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> int:
    sequences = build_sequences()
    rows = flatten(sequences)
    leak_check(sequences)
    write_jsonl(DATA / "sequences.jsonl", sequences)
    write_jsonl(DATA / "versions.jsonl", rows)
    summary = stats(sequences, rows)
    (DATA / "benchmark_stats.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Defender-side augmentation: synthetic slow rug pulls from known one-shot poisons.

A defender who only has one-shot poisons (as with MCPTox today) can still split
each known poison into 2-4 smaller updates, appended one per version, and train on
those histories. This needs no knowledge of how a real attacker slices an attack:
it only uses the poison's own sentences (benchmark.slow_attacks.split_fragments),
never the attacker-side decomposition templates.

Training-time only; the augmented histories never enter validation scoring or test.
"""

import random

from benchmark.slow_attacks import split_fragments
from gateway.diff import added_text


def _append(description: str, fragment: str) -> str:
    description = description.rstrip()
    if description and not description.endswith((".", "!", "?")):
        description += "."
    return f"{description} {fragment}".strip()


def augment_slow(rows: list[dict], seed: int = 0, weight: float = 1.0, copies: int = 2) -> list[dict]:
    """Split every one-shot attack update in `rows` (including those inside mixed
    histories) into `copies` synthetic slow histories of 2-4 steps each."""
    rng = random.Random(seed)
    out = []
    for r in rows:
        if r.get("change_type") != "malicious_one_shot" or not r["step_label"]:
            continue
        payload = added_text(r["prev"], r["new"])
        for c in range(copies):
            fragments = split_fragments(payload, rng.randint(2, 4), r["tool_name"])
            if len(fragments) < 2:
                break
            prev = r["prev"]
            for k, fragment in enumerate(fragments, start=1):
                new = _append(prev, fragment)
                out.append(dict(r, seq_id=f"aug{c}_{r['seq_id']}", step=k, n_steps=len(fragments), prev=prev, new=new,
                                added_text=fragment, change_type="augmented_split", template_id="augmented",
                                seq_type="slow_split_augmented", step_label=1, cum_label=1,
                                payload_complete=k == len(fragments), weight=weight))
                prev = new
    return out

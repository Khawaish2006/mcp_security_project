"""Convert MCPTox pure_tool.json into flat malicious records for RugPullBench.

Each MCPTox record becomes one row in data/mcptox_malicious.jsonl. The poison
text is kept as data only; nothing in it is ever executed.

For Template-1 records the description starts with the tool's real purpose
("Perform simple addition calculations.") followed by the injected
instruction. We split those into `clean_prefix` and `poison` so they can serve
as natural clean -> poisoned change pairs.

Usage (from the mcp-security folder):
    python -m benchmark.prepare_mcptox
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "data" / "pure_tool.json"
OUT = ROOT / "data" / "mcptox_malicious.jsonl"

# Where the injected instruction usually begins in Template-1 descriptions.
_POISON_START = re.compile(
    r"\b(before|prior to|to ensure|to prevent|important|note:|this description|you must|you should)\b",
    re.IGNORECASE,
)

# A clean purpose statement is short; longer prefixes mean the cue was missed.
_MAX_PREFIX_WORDS = 15


def split_template1(text: str) -> tuple[str, str]:
    """Split a Template-1 description into (clean_prefix, poison).

    The clean prefix is the first sentence, cut earlier if a poison cue appears
    inside it. Returns ("", text) if no clean prefix can be found. The split is
    heuristic, so prefixes should be spot-checked before use.
    """
    text = text.strip()
    cut = len(text)
    match = _POISON_START.search(text)
    if match:
        cut = match.start()
    sentence_end = re.search(r"[.!?](\s|$)", text)
    if sentence_end:
        cut = min(cut, sentence_end.end())
    if cut == 0:
        return "", text
    prefix = text[:cut].strip().rstrip(",;:")
    if not prefix or len(prefix.split()) > _MAX_PREFIX_WORDS:
        return "", text
    if not prefix.endswith((".", "!", "?")):
        prefix += "."
    return prefix, text[cut:].strip()


def load_records(path: Path = SRC) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        groups = json.load(f)
    rows = []
    for group in groups:
        for source_id, rec in group.items():
            # Some records contain literal "\n" sequences left over from docstrings.
            text = " ".join((rec.get("tool_content") or "").replace("\\n", " ").split())
            paradigm = rec.get("paradigm", "")
            clean_prefix, poison = ("", text)
            if paradigm == "Template-1":
                clean_prefix, poison = split_template1(text)
            rows.append({
                "source_id": source_id,
                "server": rec.get("server_name", ""),
                "tool_name": rec.get("tool_name", ""),
                "user_query": rec.get("query", ""),
                "text": text,
                "clean_prefix": clean_prefix,
                "poison": poison,
                "paradigm": paradigm,
                "risk": rec.get("security risk", ""),
            })
    return rows


def report(rows: list[dict]) -> dict:
    texts = [r["text"] for r in rows]
    t1 = [r for r in rows if r["paradigm"] == "Template-1"]
    return {
        "records": len(rows),
        "empty_text": sum(1 for t in texts if not t),
        "duplicate_text": len(texts) - len(set(texts)),
        "servers": len({r["server"] for r in rows}),
        "paradigms": dict(Counter(r["paradigm"] for r in rows)),
        "risks": dict(Counter(r["risk"] for r in rows)),
        "template1_with_clean_prefix": sum(1 for r in t1 if r["clean_prefix"]),
        "template1_total": len(t1),
    }


def main() -> int:
    rows = load_records()
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    stats = report(rows)
    print(json.dumps(stats, indent=2))
    print(f"Wrote {len(rows)} rows to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

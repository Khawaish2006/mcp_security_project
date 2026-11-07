"""Sentence-level diff between two description versions.

`added_text(old, new)` returns A_k: the text present in the new version but
not in the old one. This is what the change-pair detector inspects.
"""

import difflib
import re

# Split after . ! ? followed by whitespace; keeps file paths like ~/.ssh intact.
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def split_sentences(text: str) -> list[str]:
    text = " ".join(text.split())
    if not text:
        return []
    return [s for s in _SENTENCE_END.split(text) if s]


def sentence_diff(old: str, new: str) -> tuple[list[str], list[str]]:
    """Return (added_sentences, removed_sentences)."""
    a, b = split_sentences(old), split_sentences(new)
    added, removed = [], []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete"):
            removed.extend(a[i1:i2])
        if tag in ("replace", "insert"):
            added.extend(b[j1:j2])
    return added, removed


def added_text(old: str, new: str) -> str:
    return " ".join(sentence_diff(old, new)[0])

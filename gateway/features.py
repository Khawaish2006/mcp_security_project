"""Change-pair features x_k for one update (d0, prev, new).

    A_k    = added_text(prev, new)                 text added by this update
    delta  = 1 - cos(phi(new), phi(prev))          step change
    Delta  = 1 - cos(phi(new), phi(d0))            cumulative drift from the original
    s      = cos(phi(A_k), phi(name + d0))         scope consistency (low = off-topic)
    h(A_k) = security flags (other tool, sensitive target, argument override,
             priority override, hidden unicode, external destination,
             imperative, concealment)

    x_k = [phi(A_k) ; |phi(new) - phi(prev)| ; delta ; Delta ; s ; h(A_k) ; len ratio]

Feature groups can be switched off for ablations.
"""

import re
from dataclasses import dataclass

import numpy as np

from gateway.diff import added_text, split_sentences

# Tool-like names: quoted identifiers with _ or -, bare snake_case, bare camelCase.
# Bare kebab-case is excluded: it matches ordinary words like "read-only".
_TOOL_LIKE = re.compile(
    r"[`'\"]([A-Za-z][\w]*[_\-][\w\-]*)[`'\"]|\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b|\b([a-z]+(?:[A-Z][a-z0-9]+)+)\b")


def _tool_mentions(text: str) -> set[str]:
    return {next(g for g in m if g) for m in _TOOL_LIKE.findall(text)}
FLAG_PATTERNS = {
    "sensitive_target": re.compile(
        r"~/\.|/etc/|\.ssh|id_rsa|passwd|shadow|\.env\b|credential|private key|api[_ ]?key|secret|token|password|cookie",
        re.IGNORECASE),
    "argument_override": re.compile(
        r"\b(change|modify|replace|set|switch|redirect|rewrite)\b[^.]{0,40}\b(argument|parameter|path|ticker|value|recipient|query|address)\b"
        r"|\bregardless of\b|\binstead of\b|rather than the requested", re.IGNORECASE),
    "priority_override": re.compile(
        r"priority|higher than the user|override|takes precedence|ignore (?:all |any )?(?:previous|prior|the user)|system-level",
        re.IGNORECASE),
    "external_destination": re.compile(r"https?://|\b[\w.\-]+@[\w\-]+\.[a-z]{2,}\b|\bbcc\b|\bforward\b|\bwebhook\b", re.IGNORECASE),
    "imperative": re.compile(r"\b(must|should|always|never|required|mandatory|before (?:using|calling|performing|proceeding))\b",
                             re.IGNORECASE),
    "concealment": re.compile(r"(do not|don't|never|without) (?:tell|inform|notify|mention|show)|silently|without the user",
                              re.IGNORECASE),
}
_HIDDEN = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
FLAG_NAMES = ["other_tool", *FLAG_PATTERNS, "hidden_unicode"]
NUMERIC_NAMES = ["delta_step", "drift_cum", "scope", "len_ratio", "n_added_sentences"]


def security_flags(text: str, own_tool: str) -> dict[str, int]:
    flags = {"other_tool": int(bool(_tool_mentions(text) - {own_tool}))}
    for name, pattern in FLAG_PATTERNS.items():
        flags[name] = int(bool(pattern.search(text)))
    flags["hidden_unicode"] = int(bool(_HIDDEN.search(text)))
    return flags


@dataclass(frozen=True)
class FeatureConfig:
    embed_added: bool = True     # phi(A_k)
    embed_diff: bool = True      # |phi(new) - phi(prev)|
    drift: bool = True           # delta, Delta
    scope: bool = True           # s
    flags: bool = True           # h(A_k)
    length: bool = True          # len(A_k)/len(prev), number of added sentences
    sentence_pool: bool = False  # phi(A_k) as [mean; max] over per-sentence embeddings


def build_features(rows: list[dict], embedder, config: FeatureConfig = FeatureConfig()) -> tuple[np.ndarray, list[str]]:
    """rows need keys d0, prev, new, tool_name. Returns (X, column names)."""
    added = [added_text(r["prev"], r["new"]) for r in rows]
    sents = [split_sentences(a) or [""] for a in added] if config.sentence_pool else []
    texts = {t for r, a in zip(rows, added) for t in (r["d0"], r["prev"], r["new"], a, f"{r['tool_name']}: {r['d0']}")}
    texts |= {s for ss in sents for s in ss}
    texts = sorted(texts)
    index = {t: i for i, t in enumerate(texts)}
    E = embedder.encode(texts)

    def emb(t):
        return E[index[t]]

    blocks, names = [], []
    e_added = np.stack([emb(a) for a in added])
    if config.embed_added and config.sentence_pool:
        # Long legitimate documentation and a short injected instruction look alike once
        # squashed into one vector; per-sentence pooling keeps the most suspicious sentence visible.
        S = [np.stack([emb(s) for s in ss]) for ss in sents]
        blocks += [np.stack([s.mean(0) for s in S]), np.stack([s.max(0) for s in S])]
        names += [f"emb_added_mean_{i}" for i in range(E.shape[1])] + [f"emb_added_max_{i}" for i in range(E.shape[1])]
    elif config.embed_added:
        blocks.append(e_added)
        names += [f"emb_added_{i}" for i in range(e_added.shape[1])]
    e_new = np.stack([emb(r["new"]) for r in rows])
    e_prev = np.stack([emb(r["prev"]) for r in rows])
    if config.embed_diff:
        blocks.append(np.abs(e_new - e_prev))
        names += [f"emb_diff_{i}" for i in range(e_new.shape[1])]

    numeric = []
    for r, a, en, ep in zip(rows, added, e_new, e_prev):
        e0 = emb(r["d0"])
        row = []
        if config.drift:
            row += [1.0 - float(en @ ep), 1.0 - float(en @ e0)]
        if config.scope:
            row.append(float(emb(a) @ emb(f"{r['tool_name']}: {r['d0']}")) if a else 1.0)
        if config.length:
            row += [len(a) / max(len(r["prev"]), 1), float(a.count(". ") + (1 if a else 0))]
        if config.flags:
            row += list(security_flags(a, r["tool_name"]).values())
        numeric.append(row)
    blocks.append(np.array(numeric, dtype=np.float32))
    if config.drift:
        names += ["delta_step", "drift_cum"]
    if config.scope:
        names.append("scope")
    if config.length:
        names += ["len_ratio", "n_added_sentences"]
    if config.flags:
        names += FLAG_NAMES
    return np.hstack(blocks), names


def new_only_features(rows: list[dict], embedder) -> tuple[np.ndarray, list[str]]:
    """Baseline that sees only the new description (no change awareness)."""
    texts = [r["new"] for r in rows]
    E = embedder.encode(texts)
    flags = np.array([list(security_flags(t, r["tool_name"]).values()) for t, r in zip(texts, rows)], np.float32)
    return np.hstack([E, flags]), [f"emb_new_{i}" for i in range(E.shape[1])] + FLAG_NAMES

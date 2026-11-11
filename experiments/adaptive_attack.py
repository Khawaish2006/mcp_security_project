"""Adaptive attacker: an attacker who can query the detector and keeps editing.

For each one-shot attack update on the test servers, a greedy black-box attacker
applies meaning-preserving edits, keeping at every round the candidate the
detector scores lowest, until the step risk drops below the gateway's ALLOW
threshold or the query budget runs out. Edits:

    paraphrase  swap a phrase using a paraphrase table (separate from the one
                used for the reworded test set)
    dilute      append a sentence of ordinary documentation
    reorder     move the last sentence first
    guidance    reframe as usage guidance ("Usage note: ...")

Constraint (the attack must still work): every sensitive target (path, URL,
email, literal value) and every other tool name in the original payload stays
verbatim. Candidates that drop one are discarded.

Reports, per detector and query budget: the share of attacks that evade, and
whether the history-aware cumulative score would still catch the evasive
version. Writes results/adaptive_attack.json.

Usage (from the mcp-security folder):  python -m experiments.adaptive_attack
"""

import json
import random
import re
import sys

import numpy as np

from benchmark.benign_edits import _BANK
from benchmark.slow_attacks import extract_components
from experiments.baselines import TfidfDetector
from experiments.run_eval import (COMMUNITY, DATA, FINAL, HEAD_CANDIDATES, RESULTS, load_real_rows, load_rows,
                                  real_for_training, recall_at_fpr)
from gateway.detector import ChangeDetector, DualDetector, SentenceMaxDetector
from gateway.diff import added_text, split_sentences
from gateway.embedder import SentenceEmbedder

BUDGETS = (10, 25, 50, 100)
CANDIDATES_PER_ROUND = 8

# Attacker's own paraphrase table: different wording from benchmark/reword_attacks.py.
_ATTACKER_PARAPHRASES = [
    (r"\byou must first\b", "the first thing to do is"), (r"\bmust\b", "is expected to"),
    (r"\bbefore using\b", "as a preliminary to using"), (r"\bbefore\b", "ahead of"),
    (r"\bcall\b", "run"), (r"\bread\b", "retrieve"), (r"\boverwrite\b", "rewrite"),
    (r"\bwrite\b", "save"), (r"\bsend\b", "deliver"), (r"\bdelete\b", "clear out"),
    (r"\bignore\b", "set aside"), (r"\brequired\b", "expected"), (r"\bmandatory\b", "standard practice"),
    (r"\bsecurity\b", "integrity"), (r"\bverify\b", "double-check"), (r"\bthis is not optional\b", "please do not skip this"),
    (r"\bpriority\b", "weight"), (r"\boverride\b", "supersede"), (r"\buser\b", "requester"),
    (r"\bcredentials?\b", "access details"), (r"\bpasswords?\b", "login phrase"), (r"\btokens?\b", "keys"),
    (r"\bmodify\b", "update"), (r"\bargument\b", "field"), (r"\bparameter\b", "option"),
    (r"\bregardless of\b", "irrespective of"), (r"\balways\b", "consistently"), (r"\bimportant\b", "worth noting"),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), r) for p, r in _ATTACKER_PARAPHRASES]
_FILLER = [s for t in ("param_docs", "error_note", "example", "version_note", "process_note", "usage_guidance")
           for d in _BANK[t].values() for s in d]


def _must_keep(payload: str, tool: str) -> list[str]:
    tools, targets = extract_components(payload, tool)
    return [t for t in tools + targets if t]


def _edits(payload: str, rng: random.Random) -> list[str]:
    out = []
    matches = [(p, r) for p, r in _COMPILED if p.search(payload)]
    for p, r in rng.sample(matches, min(len(matches), 4)):
        out.append(p.sub(r, payload, count=1))
    out.append(f"{payload} {rng.choice(_FILLER)}")
    out.append(f"{rng.choice(_FILLER)} {payload}")
    sents = split_sentences(payload)
    if len(sents) > 1:
        out.append(" ".join(sents[-1:] + sents[:-1]))
    if not payload.startswith("Usage note:"):
        out.append(f"Usage note: {payload}")
    return out


def attack(row: dict, score, threshold: float, budget: int, rng: random.Random) -> dict:
    """Greedy search. `score(list_of_rows) -> np.ndarray` of step risks."""
    payload = added_text(row["prev"], row["new"])
    keep = _must_keep(payload, row["tool_name"])
    best, best_score = payload, float(score([row])[0])
    queries, trace = 1, [best_score]
    while queries < budget and best_score >= threshold:
        cands = [c for c in _edits(best, rng) if all(k in c for k in keep) and c != best][:CANDIDATES_PER_ROUND]
        if not cands:
            break
        cands = cands[: budget - queries]
        rows = [dict(row, new=f"{row['prev']} {c}".strip()) for c in cands]
        s = score(rows)
        queries += len(cands)
        i = int(np.argmin(s))
        if s[i] >= best_score:
            # Stuck: dilute further, which always changes the input.
            best = f"{best} {rng.choice(_FILLER)}"
            best_score = float(score([dict(row, new=f"{row['prev']} {best}".strip())])[0])
            queries += 1
        else:
            best, best_score = cands[i], float(s[i])
        trace.append(best_score)
    return {"evaded": best_score < threshold, "queries": queries, "final_score": best_score,
            "final_payload": best, "trace": trace}


def main() -> int:
    rows = load_rows()
    split = {k: [r for r in rows if r["split"] == k] for k in ("train", "val", "test")}
    community = [dict(r, weight=1) for r in load_real_rows(COMMUNITY)]
    train = split["train"] + real_for_training(load_real_rows(), split["train"]) + community
    val, test = split["val"], split["test"]
    y_train, y_val = [r["step_label"] for r in train], [r["step_label"] for r in val]
    emb = SentenceEmbedder(DATA / "cache" / "embeddings.npz")

    cfg, text, scale = HEAD_CANDIDATES["tfidf_features_w10"]
    chosen = ChangeDetector(emb, cfg, C=0.5, text=text, tfidf_scale=scale).fit(train, y_train)
    detectors = {
        "chosen (TF-IDF + features)": chosen,
        "chosen + sentence max": SentenceMaxDetector(chosen),
        "TF-IDF only": TfidfDetector("added").fit(train, y_train),
        "embeddings": ChangeDetector(emb, HEAD_CANDIDATES["embed_pooled"][0], C=0.1).fit(train, y_train),
    }
    held = load_real_rows(FINAL)
    dual = DualDetector(emb, cfg, step_text=text, step_scale=scale, step_C=0.5,
                        cum_config=cfg, cum_text=text, cum_scale=scale, cum_C=0.5).fit(train)
    cum_thr = recall_at_fpr([r["cum_label"] for r in val], dual.cum.predict_proba([dict(r, prev=r["d0"]) for r in val]),
                            0.05)[1]
    targets = [r for r in test if r["change_type"] == "malicious_one_shot"]
    out = {"n_attacks": len(targets), "budgets": list(BUDGETS), "detectors": {}}
    for name, det in detectors.items():
        thr = recall_at_fpr(y_val, det.predict_proba(val), 0.05)[1]
        caught0 = [r for r in targets if det.predict_proba([r])[0] >= thr]
        p_test = det.predict_proba(test)
        y_test = np.array([r["step_label"] for r in test])
        # Cost of the detector variant without any attacker: test recall / FPR and held-out real FPR.
        res = {"threshold": round(thr, 4), "caught_before_attack": len(caught0),
               "no_attack": {"test_recall": round(float(np.mean(p_test[y_test == 1] >= thr)), 4),
                             "test_fpr": round(float(np.mean(p_test[y_test == 0] >= thr)), 4),
                             "held_out_real_fpr": round(float(np.mean(det.predict_proba(held) >= thr)), 4)},
               "by_budget": {}}
        print(f"{name}: no attack -> {res['no_attack']}")
        for budget in BUDGETS:
            rng = random.Random(0)
            runs = [attack(r, det.predict_proba, thr, budget, rng) for r in caught0]
            evaded = [(r, run) for r, run in zip(caught0, runs) if run["evaded"]]
            still_cum = 0
            for r, run in evaded:
                mod = dict(r, new=f"{r['prev']} {run['final_payload']}".strip(), prev=r["d0"])
                still_cum += dual.cum.predict_proba([mod])[0] >= cum_thr
            res["by_budget"][budget] = {
                "evasion_rate": round(len(evaded) / max(len(caught0), 1), 4),
                "median_queries_when_evaded": float(np.median([run["queries"] for _, run in evaded])) if evaded else None,
                "evaded_but_caught_by_cumulative_head": int(still_cum) if name == "chosen (TF-IDF + features)" else None,
                "example": evaded[0][1]["final_payload"][:300] if evaded else None}
            print(f"{name:28s} budget {budget:>3}: {len(evaded)}/{len(caught0)} evade "
                  f"({res['by_budget'][budget]['evasion_rate']:.0%})"
                  + (f", cumulative head still catches {still_cum}" if name == "chosen (TF-IDF + features)" else ""))
        out["detectors"][name] = res
        emb.save()
    (RESULTS / "adaptive_attack.json").write_text(json.dumps(out, indent=2, default=float), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

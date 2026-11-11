"""Generalization stress tests for the step detector's text model.

Compares four detectors on inputs unlike their training data:
    embed           current model: sentence-pooled embeddings of the added text + flags
    tfidf_baseline  TF-IDF of the added text alone
    tfidf_features  TF-IDF of the added text + flags, drift and scope features
    hybrid          TF-IDF + sentence-pooled embeddings + flags, drift and scope

Each detector's settings (C, TF-IDF weight) are chosen on validation recall at FPR <= 5%.
Every test uses the threshold that gives FPR <= 5% on that model's own validation data:
    standard          test servers (never seen)
    softened          attacks with the giveaway words removed
    reworded          attacks rewritten in words the training data never uses
    template_holdout  phrasings never seen (train on even template variants, test on odd)
    unseen_paradigm   one MCPTox attack style removed from training (mean of 3)
    unseen_slow       no slow attacks in training; recall on slow attacks
    real_dev          the 513 community changes (development set): false alarms

The final held-out set is NOT read here. Writes results/generalization.json.
Usage (from the mcp-security folder):  python -m experiments.generalization
"""

import json
import sys

import numpy as np
from sklearn.metrics import roc_auc_score

from benchmark.reword_attacks import reword_update
from experiments.baselines import TfidfDetector
from experiments.run_eval import (COMMUNITY, DATA, RESULTS, load_real_rows, load_rows, real_for_training,
                                  recall_at_fpr)
from gateway.detector import ChangeDetector
from gateway.embedder import SentenceEmbedder
from gateway.features import FeatureConfig

EMBED_CFG = FeatureConfig(embed_diff=False, drift=False, scope=False, sentence_pool=True)
TFIDF_CFG = FeatureConfig(embed_added=False, embed_diff=False)
HYBRID_CFG = FeatureConfig(embed_diff=False, sentence_pool=True)
GRID = [(C, s) for C in (0.1, 0.5, 2.0) for s in (1.0, 3.0, 10.0)]


def variant(row):
    tid = row["template_id"]
    last = tid.rsplit(":", 1)[-1]
    return int(last) % 2 if last.isdigit() and not tid.startswith(("mcptox", "real", "bundle")) else None


def evaluate(make, train, val, test_rows, labels) -> tuple[np.ndarray, float]:
    """Fit, take the validation FPR<=5% threshold, return (test scores, threshold)."""
    m = make().fit(train, [r[labels] for r in train])
    thr = recall_at_fpr([r[labels] for r in val], m.predict_proba(val), 0.05)[1]
    return m, thr


def rates(p, y, thr):
    p, y = np.asarray(p), np.asarray(y)
    rec = float(np.mean(p[y == 1] >= thr)) if (y == 1).any() else None
    fpr = float(np.mean(p[y == 0] >= thr)) if (y == 0).any() else None
    return rec, fpr


def main() -> int:
    rows = load_rows()
    split = {k: [r for r in rows if r["split"] == k] for k in ("train", "val", "test")}
    real_dev = load_real_rows()
    community = load_real_rows(COMMUNITY)
    train = split["train"] + real_for_training(real_dev, split["train"])
    val, test = split["val"], split["test"]
    emb = SentenceEmbedder(DATA / "cache" / "embeddings.npz")
    y_val = [r["step_label"] for r in val]

    def tune(text, cfg):
        best = None
        for C, s in GRID:
            p = ChangeDetector(emb, cfg, C=C, text=text, tfidf_scale=s).fit(
                train, [r["step_label"] for r in train]).predict_proba(val)
            score = (recall_at_fpr(y_val, p, 0.05)[0], roc_auc_score(y_val, p))
            if best is None or score > best[0]:
                best = (score, C, s)
        print(f"   tuned {text}: C={best[1]}, tfidf weight={best[2]}, val recall at FPR<=5% = {best[0][0]:.3f}")
        return best[1], best[2]

    print("tuning on validation")
    tf_C, tf_s = tune("tfidf", TFIDF_CFG)
    hy_C, hy_s = tune("hybrid", HYBRID_CFG)
    makers = {
        "embed": lambda: ChangeDetector(emb, EMBED_CFG, C=0.1),
        "tfidf_baseline": lambda: TfidfDetector("added"),
        "tfidf_features": lambda: ChangeDetector(emb, TFIDF_CFG, C=tf_C, text="tfidf", tfidf_scale=tf_s),
        "hybrid": lambda: ChangeDetector(emb, HYBRID_CFG, C=hy_C, text="hybrid", tfidf_scale=hy_s),
    }
    attacks = [r for r in test if r["step_label"] == 1]
    reworded_pairs = [(r, reword_update(r)) for r in attacks if reword_update(r)["new"] != r["new"]]
    slow_ids = {r["seq_id"] for r in rows if r["change_type"].startswith("malicious_slow")}
    test_benign = [r for r in test if r["step_label"] == 0]
    out = {"settings": {"tfidf_features": {"C": tf_C, "tfidf_weight": tf_s}, "hybrid": {"C": hy_C, "tfidf_weight": hy_s}},
           "results": {}}

    for name, make in makers.items():
        print(f"testing {name}")
        res = {}
        m, thr = evaluate(make, train, val, test, "step_label")
        p = m.predict_proba(test)
        y = [r["step_label"] for r in test]
        res["standard"] = dict(zip(("recall", "fpr"), rates(p, y, thr)), auc=float(roc_auc_score(y, p)))
        soft = [r for r in attacks if r["style"] == "softened"]
        res["softened_recall"] = rates(m.predict_proba(soft), [1] * len(soft), thr)[0]
        orig_p = m.predict_proba([a for a, _ in reworded_pairs])
        new_p = m.predict_proba([b for _, b in reworded_pairs])
        res["reworded"] = {"n": len(reworded_pairs), "recall_original": rates(orig_p, [1] * len(orig_p), thr)[0],
                           "recall_reworded": rates(new_p, [1] * len(new_p), thr)[0]}
        res["real_dev_fpr"] = rates(m.predict_proba(community), [0] * len(community), thr)[1]

        tr = [r for r in train if variant(r) in (0, None)]
        te = [r for r in test if variant(r) in (1, None)]
        m2, thr2 = evaluate(make, tr, val, te, "step_label")
        res["template_holdout"] = dict(zip(("recall", "fpr"), rates(m2.predict_proba(te), [r["step_label"] for r in te], thr2)))

        lopo = []
        for paradigm in ("Template-1", "Template-2", "Template-3"):
            tr = [r for r in train if r["paradigm"] != paradigm]
            va = [r for r in val if r["paradigm"] != paradigm]
            te = [r for r in test if r["paradigm"] == paradigm and r["step_label"] == 1] + test_benign
            m3, thr3 = evaluate(make, tr, va, te, "step_label")
            lopo.append(rates(m3.predict_proba(te), [r["step_label"] for r in te], thr3))
        res["unseen_paradigm"] = {"recall": float(np.mean([a for a, _ in lopo])), "fpr": float(np.mean([b for _, b in lopo]))}

        tr = [r for r in train if r["seq_id"] not in slow_ids]
        va = [r for r in val if r["seq_id"] not in slow_ids]
        te = [r for r in test if r["seq_id"] in slow_ids and r["step_label"] == 1] + test_benign
        m4, thr4 = evaluate(make, tr, va, te, "step_label")
        res["unseen_slow"] = dict(zip(("recall", "fpr"), rates(m4.predict_proba(te), [r["step_label"] for r in te], thr4)))
        out["results"][name] = res
        emb.save()

    (RESULTS / "generalization.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    pct = lambda x: "  n/a " if x is None else f"{100 * x:5.1f}%"  # noqa: E731
    print("\nrecall = attacks caught, FPR = legitimate updates flagged (all at each model's validation FPR<=5% threshold)")
    print(f"{'test':34s}" + "".join(f"{n:>16s}" for n in makers))
    lines = [("standard recall", lambda r: r["standard"]["recall"]), ("standard FPR", lambda r: r["standard"]["fpr"]),
             ("softened attacks recall", lambda r: r["softened_recall"]),
             ("reworded: original recall", lambda r: r["reworded"]["recall_original"]),
             ("reworded: reworded recall", lambda r: r["reworded"]["recall_reworded"]),
             ("unseen phrasing recall", lambda r: r["template_holdout"]["recall"]),
             ("unseen phrasing FPR", lambda r: r["template_holdout"]["fpr"]),
             ("unseen attack style recall", lambda r: r["unseen_paradigm"]["recall"]),
             ("unseen slow attacks recall", lambda r: r["unseen_slow"]["recall"]),
             ("real changes (dev, 513) FPR", lambda r: r["real_dev_fpr"])]
    for label, get in lines:
        print(f"{label:34s}" + "".join(f"{pct(get(out['results'][n])):>16s}" for n in makers))
    return 0


if __name__ == "__main__":
    sys.exit(main())

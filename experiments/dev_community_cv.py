"""Development check: train on the community development changes too.

The 513 community changes were scored once and are now development data. Here
they join training (official real changes too, weighted), and their false-alarm
rate is measured by 5-fold cross-validation grouped by repository, alongside
test-server recall and FPR. The final held-out set is not read.

Usage (from the mcp-security folder):  python -m experiments.dev_community_cv
"""

import sys

import numpy as np
from sklearn.model_selection import GroupKFold

from experiments.baselines import TfidfDetector
from experiments.generalization import EMBED_CFG, TFIDF_CFG, rates
from experiments.run_eval import COMMUNITY, DATA, load_real_rows, load_rows, real_for_training, recall_at_fpr
from gateway.detector import ChangeDetector
from gateway.embedder import SentenceEmbedder

WEIGHTS = (1, 5, 20)


def main() -> int:
    rows = load_rows()
    split = {k: [r for r in rows if r["split"] == k] for k in ("train", "val", "test")}
    train = split["train"] + real_for_training(load_real_rows(), split["train"])
    val, test = split["val"], split["test"]
    community = load_real_rows(COMMUNITY)
    emb = SentenceEmbedder(DATA / "cache" / "embeddings.npz")
    makers = {"tfidf_features": lambda: ChangeDetector(emb, TFIDF_CFG, C=2.0, text="tfidf", tfidf_scale=3.0),
              "tfidf_baseline": lambda: TfidfDetector("added"),
              "embed": lambda: ChangeDetector(emb, EMBED_CFG, C=0.1)}
    groups = [r["server"] for r in community]
    y_val, y_test = [r["step_label"] for r in val], [r["step_label"] for r in test]
    print(f"{'model':16s} {'weight':>6s} {'test recall':>12s} {'test FPR':>9s} {'community FPR (CV)':>19s}")
    for name, make in makers.items():
        for w in WEIGHTS:
            cv_flag, recs, fprs = np.zeros(len(community), bool), [], []
            for tr_i, te_i in GroupKFold(n_splits=5).split(community, groups=groups):
                extra = [dict(community[i], weight=w) for i in tr_i]
                data = train + extra
                m = make().fit(data, [r["step_label"] for r in data])
                thr = recall_at_fpr(y_val, m.predict_proba(val), 0.05)[1]
                cv_flag[te_i] = m.predict_proba([community[i] for i in te_i]) >= thr
                rec, fpr = rates(m.predict_proba(test), y_test, thr)
                recs.append(rec)
                fprs.append(fpr)
            print(f"{name:16s} {w:>6d} {np.mean(recs):>11.1%} {np.mean(fprs):>8.1%} {cv_flag.mean():>18.1%}")
        emb.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())

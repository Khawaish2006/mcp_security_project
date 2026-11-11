"""Development check: how much weight to give real changes in training.

Uses ONLY the development real set (data/real_histories.jsonl, official servers)
and the benchmark's train/val splits. The held-out community set is not read.

For each weight w, the step head is trained on train + real changes of the other
server groups (weighted w; w = 0 means real changes are left out) and scored on
the held-out group's real changes (grouped cross-validation), plus validation
recall at FPR <= 5% so a lower false-alarm rate is not bought with missed attacks.

Usage (from the mcp-security folder):  python -m experiments.dev_real_weight
"""

import sys

import numpy as np
from sklearn.model_selection import GroupKFold

from experiments.run_eval import DATA, load_real_rows, load_rows, recall_at_fpr
from gateway.detector import ChangeDetector
from gateway.embedder import SentenceEmbedder
from gateway.features import FeatureConfig

WEIGHTS = (0, 20)
CONFIGS = {
    "whole-text embedding": FeatureConfig(embed_diff=False),
    "whole-text, no length": FeatureConfig(embed_diff=False, length=False),
    "sentence pooling": FeatureConfig(embed_diff=False, sentence_pool=True),
    "sentence pooling, no length": FeatureConfig(embed_diff=False, sentence_pool=True, length=False),
}


def main() -> int:
    rows = load_rows()
    train = [r for r in rows if r["split"] == "train"]
    val = [r for r in rows if r["split"] == "val"]
    real = load_real_rows(DATA / "real_histories.jsonl")
    emb = SentenceEmbedder(DATA / "cache" / "embeddings.npz")
    groups = [r["server"] for r in real]
    y_val = [r["step_label"] for r in val]
    print(f"dev real changes: {len(real)} from {len(set(groups))} servers")
    for name, cfg in CONFIGS.items():
        for w in WEIGHTS:
            cv_p = np.zeros(len(real))
            val_recalls = []
            for tr_i, te_i in GroupKFold(n_splits=5).split(real, groups=groups):
                extra = [dict(real[i], weight=w) for i in tr_i] if w else []
                d = ChangeDetector(emb, cfg, C=0.5).fit(train + extra, [r["step_label"] for r in train + extra])
                cv_p[te_i] = d.predict_proba([real[i] for i in te_i])
                val_recalls.append(recall_at_fpr(y_val, d.predict_proba(val), 0.05)[0])
            print(f"{name:28s} weight {w:>2}: dev real FPR at 0.5 = {np.mean(cv_p >= 0.5):.3f}, "
                  f"mean risk {np.mean(cv_p):.3f}, val recall at FPR<=5% = {np.mean(val_recalls):.3f}")
            emb.save()
    emb.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())

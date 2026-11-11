"""TF-IDF baselines: the "simpler algorithm" a reviewer will ask about.

    tfidf_new    TF-IDF of the new description alone (no change awareness)
    tfidf_added  TF-IDF of the text added by the update (change-aware, no embeddings)

Both feed class-weighted logistic regression, like the main detector.
"""

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from gateway.diff import added_text


class TfidfDetector:
    def __init__(self, mode: str = "new", C: float = 1.0, seed: int = 0):
        if mode not in ("new", "added"):
            raise ValueError(mode)
        self.mode = mode
        self.vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)
        self.model = LogisticRegression(C=C, class_weight="balanced", max_iter=5000, random_state=seed)

    def _texts(self, rows: list[dict]) -> list[str]:
        if self.mode == "new":
            return [r["new"] for r in rows]
        return [added_text(r["prev"], r["new"]) or "(no added text)" for r in rows]

    def fit(self, rows: list[dict], y) -> "TfidfDetector":
        w = np.array([r.get("weight", 1.0) for r in rows])
        self.model.fit(self.vec.fit_transform(self._texts(rows)), np.asarray(y), sample_weight=w)
        return self

    def predict_proba(self, rows: list[dict]) -> np.ndarray:
        if not rows:
            return np.zeros(0)
        return self.model.predict_proba(self.vec.transform(self._texts(rows)))[:, 1]

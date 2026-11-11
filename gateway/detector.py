"""Layer 1: change-pair detector.

    r_k = P(y_k = 1 | x_k) = sigmoid(w^T x_k + b)

trained with class-weighted logistic regression (L2).

DualDetector pairs two such models with the same features:
    step head        on (prev -> new),  label: this update belongs to an attack
    cumulative head  on (d0   -> new),  label: attack content was added at any point since approval
Training the cumulative head on cumulative pairs keeps r_cum calibrated; reusing
the step model on (d0 -> new) pairs mis-scores long benign histories.
"""

from pathlib import Path

import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from gateway.features import FeatureConfig, build_features, new_only_features, security_flags
from gateway.diff import added_text, split_sentences


TEXT_MODES = ("embed", "tfidf", "hybrid")


class ChangeDetector:
    """text = "embed": dense features only (embeddings of the added text, drift, scope, flags).
    text = "tfidf":  TF-IDF of the added text + the non-embedding dense features (config decides which).
    text = "hybrid": TF-IDF of the added text + all dense features, embeddings included.
    The TF-IDF block is multiplied by tfidf_scale to balance it against the standardized dense block.
    """

    def __init__(self, embedder, config: FeatureConfig = FeatureConfig(), new_only: bool = False,
                 C: float = 0.5, seed: int = 0, text: str = "embed", tfidf_scale: float = 1.0):
        if text not in TEXT_MODES:
            raise ValueError(text)
        self.embedder = embedder
        self.config = config
        self.new_only = new_only
        self.text = text
        self.tfidf_scale = tfidf_scale
        self.scaler = StandardScaler()
        self.vec = None if text == "embed" else TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)
        self.model = LogisticRegression(C=C, class_weight="balanced", max_iter=5000, random_state=seed)
        self.feature_names: list[str] = []

    def _features(self, rows: list[dict]) -> np.ndarray:
        if self.new_only:
            X, names = new_only_features(rows, self.embedder)
        else:
            X, names = build_features(rows, self.embedder, self.config)
        self.feature_names = names
        return X

    def _matrix(self, rows: list[dict], fit: bool):
        X = self._features(rows)
        dense = self.scaler.fit_transform(X) if fit else self.scaler.transform(X)
        if self.vec is None:
            return dense
        texts = [added_text(r["prev"], r["new"]) or "(no added text)" for r in rows]
        T = self.vec.fit_transform(texts) if fit else self.vec.transform(texts)
        self.feature_names = [f"tfidf:{t}" for t in self.vec.get_feature_names_out()] + self.feature_names
        return sparse.hstack([T * self.tfidf_scale, sparse.csr_matrix(dense)]).tocsr()

    def fit(self, rows: list[dict], y) -> "ChangeDetector":
        """Rows may carry a "weight" (default 1), e.g. to up-weight scarce real changes."""
        w = np.array([r.get("weight", 1.0) for r in rows])
        self.model.fit(self._matrix(rows, fit=True), np.asarray(y), sample_weight=w)
        return self

    def predict_proba(self, rows: list[dict]) -> np.ndarray:
        if not rows:
            return np.zeros(0)
        return self.model.predict_proba(self._matrix(rows, fit=False))[:, 1]

    @staticmethod
    def explain(prev: str, new: str, tool_name: str) -> list[str]:
        """Human-readable flags raised by the text added in this update."""
        return [name for name, on in security_flags(added_text(prev, new), tool_name).items() if on]

    def top_weights(self, k: int = 15) -> list[tuple[str, float]]:
        w = self.model.coef_[0]
        order = np.argsort(-np.abs(w))[:k]
        return [(self.feature_names[i], float(w[i])) for i in order]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.state(), path)

    def state(self) -> dict:
        return {"config": self.config, "new_only": self.new_only, "scaler": self.scaler, "model": self.model,
                "feature_names": self.feature_names, "text": self.text, "tfidf_scale": self.tfidf_scale,
                "vec": self.vec}

    @classmethod
    def from_state(cls, state: dict, embedder) -> "ChangeDetector":
        det = cls(embedder, state["config"], state["new_only"], text=state.get("text", "embed"),
                  tfidf_scale=state.get("tfidf_scale", 1.0))
        det.scaler, det.model, det.feature_names = state["scaler"], state["model"], state["feature_names"]
        det.vec = state.get("vec")
        return det

    @classmethod
    def load(cls, path: Path, embedder) -> "ChangeDetector":
        return cls.from_state(joblib.load(path), embedder)


class SentenceMaxDetector:
    """Dilution-resistant wrapper: risk = max(risk of the whole update, risk of each added sentence alone).

    Padding an injected instruction with harmless documentation lowers a whole-text score;
    it cannot lower the score of the injected sentence when that sentence is scored by itself.
    """

    def __init__(self, base):
        self.base = base

    def predict_proba(self, rows: list[dict]) -> np.ndarray:
        if not rows:
            return np.zeros(0)
        singles, owner = [], []
        for i, r in enumerate(rows):
            for s in split_sentences(added_text(r["prev"], r["new"])):
                singles.append(dict(r, new=f"{r['prev']} {s}".strip()))
                owner.append(i)
        p = self.base.predict_proba(rows)
        if singles:
            ps = self.base.predict_proba(singles)
            for i, v in zip(owner, ps):
                p[i] = max(p[i], v)
        return p


def cumulative_rows(rows: list[dict]) -> list[dict]:
    """The same updates seen as one change from the original approved version."""
    return [dict(r, prev=r["d0"]) for r in rows]


class DualDetector:
    """Step head + cumulative head. Rows need step_label and cum_label for fit().

    Each head can use its own feature set and regularization (chosen on validation data).
    """

    def __init__(self, embedder, config: FeatureConfig = FeatureConfig(), seed: int = 0,
                 cum_config: FeatureConfig | None = None, step_C: float = 0.5, cum_C: float = 0.5,
                 step_text: str = "embed", cum_text: str = "embed", step_scale: float = 1.0, cum_scale: float = 1.0):
        self.step = ChangeDetector(embedder, config, C=step_C, seed=seed, text=step_text, tfidf_scale=step_scale)
        self.cum = ChangeDetector(embedder, cum_config or config, C=cum_C, seed=seed, text=cum_text,
                                  tfidf_scale=cum_scale)

    def fit(self, rows: list[dict]) -> "DualDetector":
        self.step.fit(rows, [r["step_label"] for r in rows])
        self.cum.fit(cumulative_rows(rows), [r["cum_label"] for r in rows])
        return self

    def predict(self, rows: list[dict]) -> tuple[np.ndarray, np.ndarray]:
        """(r_step, r_cum) for each row."""
        return self.step.predict_proba(rows), self.cum.predict_proba(cumulative_rows(rows))

    def score(self, d0: str, prev: str, new: str, tool_name: str) -> tuple[float, float]:
        """(r_step, r_cum) for one update; used by the gateway."""
        r_step, r_cum = self.predict([{"d0": d0, "prev": prev, "new": new, "tool_name": tool_name}])
        return float(r_step[0]), float(r_cum[0])

    explain = staticmethod(ChangeDetector.explain)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"step": self.step.state(), "cum": self.cum.state()}, path)

    @classmethod
    def load(cls, path: Path, embedder) -> "DualDetector":
        state = joblib.load(path)
        det = cls(embedder)
        det.step = ChangeDetector.from_state(state["step"], embedder)
        det.cum = ChangeDetector.from_state(state["cum"], embedder)
        return det

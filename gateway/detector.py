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
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from gateway.features import FeatureConfig, build_features, new_only_features, security_flags
from gateway.diff import added_text


class ChangeDetector:
    def __init__(self, embedder, config: FeatureConfig = FeatureConfig(), new_only: bool = False,
                 C: float = 0.5, seed: int = 0):
        self.embedder = embedder
        self.config = config
        self.new_only = new_only
        self.scaler = StandardScaler()
        self.model = LogisticRegression(C=C, class_weight="balanced", max_iter=5000, random_state=seed)
        self.feature_names: list[str] = []

    def _features(self, rows: list[dict]) -> np.ndarray:
        if self.new_only:
            X, names = new_only_features(rows, self.embedder)
        else:
            X, names = build_features(rows, self.embedder, self.config)
        self.feature_names = names
        return X

    def fit(self, rows: list[dict], y) -> "ChangeDetector":
        X = self._features(rows)
        self.model.fit(self.scaler.fit_transform(X), np.asarray(y))
        return self

    def predict_proba(self, rows: list[dict]) -> np.ndarray:
        if not rows:
            return np.zeros(0)
        return self.model.predict_proba(self.scaler.transform(self._features(rows)))[:, 1]

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
        return {"config": self.config, "new_only": self.new_only, "scaler": self.scaler,
                "model": self.model, "feature_names": self.feature_names}

    @classmethod
    def from_state(cls, state: dict, embedder) -> "ChangeDetector":
        det = cls(embedder, state["config"], state["new_only"])
        det.scaler, det.model, det.feature_names = state["scaler"], state["model"], state["feature_names"]
        return det

    @classmethod
    def load(cls, path: Path, embedder) -> "ChangeDetector":
        return cls.from_state(joblib.load(path), embedder)


def cumulative_rows(rows: list[dict]) -> list[dict]:
    """The same updates seen as one change from the original approved version."""
    return [dict(r, prev=r["d0"]) for r in rows]


class DualDetector:
    """Step head + cumulative head. Rows need step_label and cum_label for fit()."""

    def __init__(self, embedder, config: FeatureConfig = FeatureConfig(), seed: int = 0):
        self.step = ChangeDetector(embedder, config, seed=seed)
        self.cum = ChangeDetector(embedder, config, seed=seed)

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

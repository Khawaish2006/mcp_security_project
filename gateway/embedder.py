"""Sentence embeddings phi(d) for descriptions and added text.

SentenceEmbedder wraps all-MiniLM-L6-v2 (384 dimensions, runs on CPU) and
caches vectors on disk, so repeated experiments do not re-encode text.
HashEmbedder is a fast, dependency-light stand-in with the same interface,
used by the unit tests.

All vectors are L2-normalized, so cosine similarity is a dot product.
"""

import hashlib
from pathlib import Path

import numpy as np

DIM = 384


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b))


class HashEmbedder:
    """Bag-of-words hashing embedding. No model download; for tests only."""

    name = "hash-384"

    def encode(self, texts: list[str]) -> np.ndarray:
        from sklearn.feature_extraction.text import HashingVectorizer

        vec = HashingVectorizer(n_features=DIM, ngram_range=(1, 2), alternate_sign=False, norm="l2")
        return vec.transform([t or "" for t in texts]).toarray().astype(np.float32)


class SentenceEmbedder:
    name = "all-MiniLM-L6-v2"

    def __init__(self, cache_path: Path | None = None):
        self._model = None
        self._cache: dict[str, np.ndarray] = {}
        self._cache_path = cache_path
        if cache_path and cache_path.exists():
            data = np.load(cache_path)
            self._cache = dict(zip(data["keys"].tolist(), data["vectors"]))
        self._dirty = False

    @staticmethod
    def _key(text: str) -> str:
        return hashlib.sha1(text.encode("utf-8")).hexdigest()

    def encode(self, texts: list[str]) -> np.ndarray:
        keys = [self._key(t or "") for t in texts]
        missing = sorted({(k, t or "") for k, t in zip(keys, texts) if k not in self._cache})
        if missing:
            if self._model is None:
                from sentence_transformers import SentenceTransformer

                self._model = SentenceTransformer(f"sentence-transformers/{self.name}", device="cpu")
            vectors = self._model.encode([t for _, t in missing], batch_size=64, normalize_embeddings=True,
                                         show_progress_bar=len(missing) > 500)
            for (k, _), v in zip(missing, vectors):
                self._cache[k] = v.astype(np.float32)
            self._dirty = True
        return np.stack([self._cache[k] for k in keys]) if keys else np.zeros((0, DIM), np.float32)

    def save(self) -> None:
        if self._cache_path and self._dirty:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            keys = list(self._cache)
            np.savez_compressed(self._cache_path, keys=np.array(keys), vectors=np.stack([self._cache[k] for k in keys]))
            self._dirty = False

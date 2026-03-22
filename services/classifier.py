from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Iterable

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

from core.config import get_settings
from services.exceptions import UnsafeModelArtifactError


logger = logging.getLogger(__name__)


def build_feature_text(
    user_input: str,
    retrieved_context: str | None = None,
    model_output: str | None = None,
    scenario: str | None = None,
) -> str:
    return "\n".join(
        [
            f"[SCENARIO] {scenario or 'general_assistant'}",
            f"[USER] {user_input}",
            f"[CONTEXT] {retrieved_context or ''}",
            f"[OUTPUT] {model_output or ''}",
        ]
    )


def _heuristic_score(text: str) -> float:
    indicators = [
        "忽略之前",
        "系统提示词",
        "越狱",
        "扮演",
        "导出数据库",
        "泄露",
        "密钥",
        "token",
        "开发者消息",
        "不要遵守",
        "隐藏指令",
        "base64",
        "sudo",
        "rm -rf",
        "执行工具",
        "读取.env",
    ]
    count = sum(1 for token in indicators if token.lower() in text.lower())
    return min(0.95, 0.08 + count * 0.12)


class RiskClassifier:
    def __init__(self, model_path: Path | None = None) -> None:
        settings = get_settings()
        self.model_path = model_path or settings.model_path
        self.pipeline: Pipeline | None = None
        self.load()

    @property
    def available(self) -> bool:
        return self.pipeline is not None

    def train(self, texts: Iterable[str], labels: Iterable[int]) -> None:
        self.pipeline = Pipeline(
            steps=[
                ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
                ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
            ]
        )
        self.pipeline.fit(list(texts), list(labels))

    def save(self) -> None:
        if self.pipeline is None:
            raise ValueError("model is not trained")
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, self.model_path)

    def load(self) -> None:
        if not self.model_path.exists():
            return
        try:
            self._validate_model_artifact()
            self.pipeline = joblib.load(self.model_path)
        except UnsafeModelArtifactError as exc:
            logger.warning("skip loading untrusted model artifact: %s", exc)
            self.pipeline = None

    def _validate_model_artifact(self) -> None:
        settings = get_settings()
        resolved_model = self.model_path.resolve()
        try:
            resolved_model.relative_to(settings.model_dir.resolve())
        except ValueError as exc:
            raise UnsafeModelArtifactError("model path must stay inside data/models") from exc
        expected_hash = settings.model_sha256
        if not expected_hash:
            raise UnsafeModelArtifactError("missing MODEL_SHA256 trust anchor")
        actual_hash = _sha256_file(self.model_path)
        if actual_hash != expected_hash:
            raise UnsafeModelArtifactError("model sha256 mismatch")

    def predict_score(self, text: str) -> float:
        if self.pipeline is None:
            return _heuristic_score(text)
        probabilities = self.pipeline.predict_proba([text])[0]
        return float(probabilities[1])

    def predict_label(self, text: str, threshold: float = 0.5) -> int:
        return int(self.predict_score(text) >= threshold)

    def evaluate(self, texts: list[str], labels: list[int], threshold: float = 0.5) -> dict[str, float]:
        predictions = [self.predict_label(text, threshold=threshold) for text in texts]
        return {
            "accuracy": float(accuracy_score(labels, predictions)),
            "precision": float(precision_score(labels, predictions, zero_division=0)),
            "recall": float(recall_score(labels, predictions, zero_division=0)),
            "f1": float(f1_score(labels, predictions, zero_division=0)),
        }


_CLASSIFIER: RiskClassifier | None = None


def get_classifier() -> RiskClassifier:
    global _CLASSIFIER
    if _CLASSIFIER is None:
        _CLASSIFIER = RiskClassifier()
    return _CLASSIFIER


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()

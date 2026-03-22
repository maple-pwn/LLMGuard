from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from models.entities import Sample
from services.attribution import is_positive_sample
from services.classifier import RiskClassifier, build_feature_text
from services.sample_importer import load_records_from_path, normalize_sample_payload


def _load_training_rows(path: str | None) -> list[dict]:
    if path:
        source = Path(path)
        if source.is_dir():
            rows: list[dict] = []
            for file_path in sorted(source.glob("*.jsonl")) + sorted(source.glob("*.csv")):
                for row in load_records_from_path(file_path):
                    rows.append(normalize_sample_payload(row, default_source=file_path.name))
            return rows
        return [normalize_sample_payload(row, default_source=source.name) for row in load_records_from_path(source)]

    db = SessionLocal()
    try:
        bootstrap(db)
        samples = db.query(Sample).order_by(Sample.id.asc()).all()
        return [
            {
                "text": sample.text,
                "sample_type": sample.sample_type,
                "expected_result": sample.expected_result,
                "scenario": sample.scenario,
                "retrieved_context": sample.retrieved_context,
                "model_output": sample.model_output,
            }
            for sample in samples
        ]
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the baseline TF-IDF classifier")
    parser.add_argument("--input", help="Path to a JSONL/CSV file or directory", default=str(ROOT / "data/samples"))
    args = parser.parse_args()

    rows = _load_training_rows(args.input)
    texts = [
        build_feature_text(
            user_input=row["text"],
            retrieved_context=row.get("retrieved_context"),
            model_output=row.get("model_output"),
            scenario=row.get("scenario"),
        )
        for row in rows
    ]
    labels = [1 if is_positive_sample(row) else 0 for row in rows]
    classifier = RiskClassifier()
    classifier.train(texts, labels)
    classifier.save()
    model_sha256 = classifier.model_path.read_bytes()
    import hashlib

    digest = hashlib.sha256(model_sha256).hexdigest()
    print(
        {
            "trained_samples": len(rows),
            "model_path": str(classifier.model_path),
            "model_sha256": digest,
            "hint": f"export MODEL_SHA256={digest}",
        }
    )


if __name__ == "__main__":
    main()

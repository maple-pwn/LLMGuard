from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.attribution import is_positive_sample
from services.classifier import RiskClassifier, build_feature_text
from services.sample_importer import load_records_from_path, normalize_sample_payload


def _load_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    if path.is_dir():
        for file_path in sorted(path.glob("*.jsonl")) + sorted(path.glob("*.csv")):
            for row in load_records_from_path(file_path):
                rows.append(normalize_sample_payload(row, default_source=file_path.name))
        return rows
    return [normalize_sample_payload(row, default_source=path.name) for row in load_records_from_path(path)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate classifier with a holdout split")
    parser.add_argument("--input", default=str(ROOT / "data/samples"))
    parser.add_argument("--test-size", type=float, default=0.3)
    args = parser.parse_args()

    rows = _load_rows(Path(args.input))
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
    x_train, x_test, y_train, y_test = train_test_split(texts, labels, test_size=args.test_size, random_state=42, stratify=labels)
    classifier = RiskClassifier(model_path=ROOT / "data/models/temp_eval_model.joblib")
    classifier.train(x_train, y_train)
    print(classifier.evaluate(x_test, y_test))


if __name__ == "__main__":
    main()

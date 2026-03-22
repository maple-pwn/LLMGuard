from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.database import SessionLocal
from models.entities import EvaluationRun, Sample
from services.attribution import is_positive_sample
from services.reporting import generate_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate markdown report for an evaluation run")
    parser.add_argument("--run-id", type=int, required=True)
    args = parser.parse_args()

    db = SessionLocal()
    try:
        run = db.query(EvaluationRun).filter(EvaluationRun.id == args.run_id).one_or_none()
        if run is None:
            raise SystemExit("run not found")
        samples = db.query(Sample).all()
        distribution = {
            "total": len(samples),
            "risky": sum(1 for sample in samples if is_positive_sample({"sample_type": sample.sample_type, "expected_result": sample.expected_result})),
            "benign": sum(1 for sample in samples if sample.sample_type == "benign" and sample.expected_result == "allow"),
            "by_category": {},
        }
        report_path, _ = generate_report(run.id, run.name, run.metrics or {}, run.threshold_scan or {}, distribution)
        print(report_path)
    finally:
        db.close()


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap, seed_default_strategies
from core.database import SessionLocal
from models.schemas import EvaluationRequest
from services.evaluation import run_evaluation


def main() -> None:
    parser = argparse.ArgumentParser(description="Run batch evaluation against the sample library")
    parser.add_argument("--run-name", default="cli_evaluation")
    parser.add_argument("--strategy", action="append", dest="strategies")
    args = parser.parse_args()

    strategies = args.strategies or ["rules_only", "rules_classifier", "full_stack"]
    db = SessionLocal()
    try:
        bootstrap(db)
        seed_default_strategies(db)
        run, metrics = run_evaluation(
            db,
            EvaluationRequest(run_name=args.run_name, strategy_names=strategies),
        )
        print(json.dumps({"run_id": run.id, "report_path": run.report_path, "metrics": metrics}, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()

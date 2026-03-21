from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.database import SessionLocal
from models.entities import EvaluationRun


def main() -> None:
    parser = argparse.ArgumentParser(description="Print attribution summary from an evaluation run")
    parser.add_argument("--run-id", type=int, required=True)
    args = parser.parse_args()

    db = SessionLocal()
    try:
        run = db.query(EvaluationRun).filter(EvaluationRun.id == args.run_id).one_or_none()
        if run is None:
            raise SystemExit("run not found")
        summary = {
            strategy: payload.get("attribution_summary", {})
            for strategy, payload in (run.metrics or {}).items()
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from services.compare import compare_evaluation_runs


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare multiple evaluation runs")
    parser.add_argument("--run-id", action="append", dest="run_ids", required=True, type=int)
    args = parser.parse_args()
    db = SessionLocal()
    try:
        bootstrap(db)
        result = compare_evaluation_runs(db, args.run_ids)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()

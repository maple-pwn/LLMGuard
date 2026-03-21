from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from services.rule_analysis import analyze_rule_effectiveness


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze rule effectiveness against evaluation results")
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args()
    db = SessionLocal()
    try:
        bootstrap(db)
        rows, report_path = analyze_rule_effectiveness(db, run_id=args.run_id)
        print(json.dumps({"report_path": report_path, "rows": rows[:10]}, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()

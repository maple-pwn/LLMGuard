from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from services.casebook import build_casebook


def main() -> None:
    parser = argparse.ArgumentParser(description="Build false positive/false negative casebook from evaluation results")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--owner", default="security_ops")
    args = parser.parse_args()
    db = SessionLocal()
    try:
        bootstrap(db)
        cases, report_path = build_casebook(db, run_id=args.run_id, owner=args.owner)
        print(json.dumps({"case_count": len(cases), "report_path": report_path}, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()

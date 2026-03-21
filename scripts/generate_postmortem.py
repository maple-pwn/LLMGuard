from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from services.ops_reporting import generate_postmortem


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate evaluation postmortem document")
    parser.add_argument("--title", default="evaluation_postmortem")
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args()
    db = SessionLocal()
    try:
        bootstrap(db)
        print(generate_postmortem(db, title=args.title, run_id=args.run_id))
    finally:
        db.close()


if __name__ == "__main__":
    main()

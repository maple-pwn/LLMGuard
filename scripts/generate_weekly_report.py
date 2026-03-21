from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from services.ops_reporting import generate_weekly_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate weekly operations report")
    parser.add_argument("--title", default="weekly_report")
    args = parser.parse_args()
    db = SessionLocal()
    try:
        bootstrap(db)
        print(generate_weekly_report(db, title=args.title))
    finally:
        db.close()


if __name__ == "__main__":
    main()

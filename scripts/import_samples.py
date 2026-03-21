from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from services.sample_importer import import_samples, load_records_from_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Import sample JSONL/CSV files into SQLite")
    parser.add_argument("path", help="Path to a JSONL or CSV file")
    args = parser.parse_args()
    db = SessionLocal()
    try:
        bootstrap(db)
        records = load_records_from_path(args.path)
        imported, skipped = import_samples(db, records, source=Path(args.path).name)
        print({"imported": imported, "skipped": skipped})
    finally:
        db.close()


if __name__ == "__main__":
    main()

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap, seed_default_strategies
from core.database import SessionLocal
from services.rule_engine import get_rule_engine
from services.sample_importer import import_samples, load_records_from_path


def main() -> None:
    db = SessionLocal()
    try:
        bootstrap(db)
        seed_default_strategies(db)
        get_rule_engine().reload_rules(db=db)
        total_imported = 0
        total_skipped = 0
        for path in sorted((ROOT / "data/samples").glob("*.jsonl")):
            imported, skipped = import_samples(db, load_records_from_path(path), source=path.name)
            total_imported += imported
            total_skipped += skipped
            print(f"{path.name}: imported={imported}, skipped={skipped}")
        print(f"seed completed: imported={total_imported}, skipped={total_skipped}")
    finally:
        db.close()


if __name__ == "__main__":
    main()

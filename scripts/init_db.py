from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap, seed_default_strategies
from core.database import SessionLocal
from services.rule_engine import get_rule_engine


def main() -> None:
    db = SessionLocal()
    try:
        bootstrap(db)
        seed_default_strategies(db)
        get_rule_engine().reload_rules(db=db)
        print("database initialized")
    finally:
        db.close()


if __name__ == "__main__":
    main()

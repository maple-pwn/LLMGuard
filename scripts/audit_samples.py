from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from services.sample_audit import audit_samples


def main() -> None:
    db = SessionLocal()
    try:
        bootstrap(db)
        try:
            summary, report_path = audit_samples(db)
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        print(json.dumps({"summary": summary, "report_path": report_path}, ensure_ascii=False, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()

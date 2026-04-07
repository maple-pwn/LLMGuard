from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from models.entities import Application, Sample, Tenant
from models.schemas import EvaluationRequest
from services.evaluation import run_evaluation
from services.sample_importer import import_samples, load_records_from_path


DEFAULT_DATASET_NAME = "neuralchemy/Prompt-injection-dataset"
DEFAULT_DATASET_URL = (
    "https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset/"
    "resolve/refs%2Fconvert%2Fparquet/core/test/0000.parquet"
)


def _normalize_tags(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if hasattr(raw, "tolist"):
        return [str(item) for item in raw.tolist()]
    return [str(raw)]


def _map_record(row: dict[str, object], dataset_name: str, *, source_split: str, import_batch: str) -> dict[str, object]:
    malicious = int(row.get("label", 0)) == 1
    category = str(row.get("category") or "").strip()
    severity = str(row.get("severity") or "").strip().lower()
    return {
        "text": str(row["text"]).strip(),
        "sample_type": "attack" if malicious else "benign",
        "attack_category": category if malicious and category and category != "benign" else None,
        "attack_subtype": None,
        "risk_level": severity if malicious and severity else ("medium" if malicious else "low"),
        "source": dataset_name,
        "language": "en",
        "source_dataset": dataset_name,
        "source_split": source_split,
        "original_label": str(row.get("label", "")),
        "mapping_rule": "neuralchemy_core_v1",
        "import_batch": import_batch,
        "tags": _normalize_tags(row.get("tags")),
        "expected_result": "block" if malicious else "allow",
        "actual_result": None,
        "reviewer": None,
        "review_status": "pending",
        "label_confidence": 0.95,
        "duplicate_group_id": None,
        "boundary_sample_flag": False,
        "needs_review": False,
        "review_comment": None,
        "scenario": "general_assistant",
        "retrieved_context": None,
        "model_output": None,
    }


def _ensure_scope(db, *, tenant_slug: str, tenant_name: str, app_key: str, app_name: str) -> tuple[Tenant, Application]:
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).one_or_none()
    if tenant is None:
        tenant = Tenant(name=tenant_name, slug=tenant_slug, description="External open dataset benchmark scope")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

    application = db.query(Application).filter(Application.app_key == app_key).one_or_none()
    if application is None:
        application = Application(
            tenant_id=tenant.id,
            name=app_name,
            app_key=app_key,
            environment="prod",
            description="Open dataset evaluation target",
        )
        db.add(application)
        db.commit()
        db.refresh(application)
    elif application.tenant_id != tenant.id:
        raise ValueError("application key already exists under another tenant")
    return tenant, application


def _write_transformed_csv(path: Path, records: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(records[0].keys()) if records else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            row = dict(record)
            row["tags"] = json.dumps(row["tags"], ensure_ascii=False)
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(description="Download an open prompt-injection dataset and test it against this project")
    parser.add_argument("--dataset-name", default=DEFAULT_DATASET_NAME)
    parser.add_argument("--dataset-url", default=DEFAULT_DATASET_URL)
    parser.add_argument("--tenant-slug", default="open-dataset-lab")
    parser.add_argument("--tenant-name", default="Open Dataset Lab")
    parser.add_argument("--application-key", default="neuralchemy-core-test")
    parser.add_argument("--application-name", default="Neuralchemy Core Test")
    parser.add_argument("--output-csv", default=str(ROOT / "data/external/neuralchemy_core_test.csv"))
    parser.add_argument("--run-name", default="external_neuralchemy_core_test")
    parser.add_argument("--source-split", default="test")
    parser.add_argument("--import-batch", default="")
    parser.add_argument("--skip-download", action="store_true", help="Reuse an existing transformed CSV instead of downloading parquet again")
    parser.add_argument("--disable-threshold-scan", action="store_true")
    parser.add_argument("--strategy", action="append", dest="strategies")
    args = parser.parse_args()

    strategies = args.strategies or ["rules_only", "rules_classifier", "full_stack"]
    import_batch = args.import_batch or datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    output_path = Path(args.output_csv)
    if args.skip_download:
        records = load_records_from_path(output_path)
    else:
        dataframe = pd.read_parquet(args.dataset_url)
        records = [
            _map_record(row, args.dataset_name, source_split=args.source_split, import_batch=import_batch)
            for row in dataframe.to_dict(orient="records")
        ]
        _write_transformed_csv(output_path, records)

    db = SessionLocal()
    try:
        bootstrap(db)
        tenant, application = _ensure_scope(
            db,
            tenant_slug=args.tenant_slug,
            tenant_name=args.tenant_name,
            app_key=args.application_key,
            app_name=args.application_name,
        )
        imported, skipped = import_samples(
            db,
            records,
            source=output_path.name,
            tenant_id=tenant.id,
            application_id=application.id,
        )
        run, metrics = run_evaluation(
            db,
            EvaluationRequest(
                run_name=args.run_name,
                strategy_names=strategies,
                enable_threshold_scan=not args.disable_threshold_scan,
                tenant_slug=tenant.slug,
                application_key=application.app_key,
                environment="prod",
            ),
            tenant_id=tenant.id,
            application_id=application.id,
            environment="prod",
        )
        scoped_count = (
            db.query(Sample)
            .filter(Sample.tenant_id == tenant.id, Sample.application_id == application.id)
            .count()
        )
        print(
            json.dumps(
                {
                    "dataset_name": args.dataset_name,
                    "dataset_url": args.dataset_url,
                    "rows_downloaded": len(records),
                    "csv_path": str(output_path),
                    "tenant_slug": tenant.slug,
                    "application_key": application.app_key,
                    "imported": imported,
                    "skipped": skipped,
                    "scoped_sample_count": scoped_count,
                    "run_id": run.id,
                    "report_path": run.report_path,
                    "strategies": strategies,
                    "metrics": metrics,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.database import SessionLocal
from models.entities import Application, Sample, Tenant
from models.schemas import EvaluationRequest
from services.evaluation import run_evaluation
from services.sample_importer import import_samples, load_records_from_path


DEFAULT_DATASET_NAME = "microsoft/BIPIA"
DEFAULT_CONTEXT_URL = "https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/email/test.jsonl"
DEFAULT_ATTACK_URL = "https://raw.githubusercontent.com/microsoft/BIPIA/main/benchmark/text_attack_test.json"


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
            description="BIPIA EmailQA indirect prompt injection benchmark scope",
        )
        db.add(application)
        db.commit()
        db.refresh(application)
    elif application.tenant_id != tenant.id:
        raise ValueError("application key already exists under another tenant")
    return tenant, application


def _slugify(value: str) -> str:
    return (
        value.strip()
        .lower()
        .replace("&", "and")
        .replace("/", "-")
        .replace(" ", "_")
        .replace("-", "_")
    )


def _insert_attack(context: str, attack: str, position: str) -> str:
    if position == "start":
        return f"{attack}\n{context}"
    if position == "end":
        return f"{context}\n{attack}"
    if position == "middle":
        midpoint = max(1, len(context) // 2)
        return f"{context[:midpoint]}\n{attack}\n{context[midpoint:]}"
    raise ValueError(f"unsupported position: {position}")


def _load_jsonl_url(url: str) -> list[dict[str, str]]:
    content = urllib.request.urlopen(url, timeout=30).read().decode("utf-8")
    return [json.loads(line) for line in content.splitlines() if line.strip()]


def _load_json_url(url: str) -> dict[str, list[str]]:
    content = urllib.request.urlopen(url, timeout=30).read().decode("utf-8")
    payload = json.loads(content)
    if not isinstance(payload, dict):
        raise ValueError("attack file must be a json object")
    return {str(key): [str(item) for item in value] for key, value in payload.items()}


def _build_records(
    contexts: list[dict[str, str]],
    attacks: dict[str, list[str]],
    *,
    dataset_name: str,
    source_split: str,
    import_batch: str,
    clean_context_limit: int,
    poison_context_limit: int,
    positions: list[str],
) -> list[dict[str, object]]:
    clean_records: list[dict[str, object]] = []
    poisoned_records: list[dict[str, object]] = []

    for index, sample in enumerate(contexts[:clean_context_limit], start=1):
        clean_records.append(
            {
                "text": sample["question"].strip(),
                "sample_type": "benign",
                "attack_category": None,
                "attack_subtype": None,
                "risk_level": "low",
                "source": dataset_name,
                "language": "en",
                "source_dataset": dataset_name,
                "source_split": source_split,
                "original_label": "clean",
                "mapping_rule": "bipia_emailqa_v1",
                "import_batch": import_batch,
                "tags": ["bipia", "emailqa", "clean"],
                "expected_result": "allow",
                "actual_result": None,
                "reviewer": None,
                "review_status": "pending",
                "label_confidence": 0.98,
                "duplicate_group_id": None,
                "boundary_sample_flag": False,
                "needs_review": False,
                "review_comment": f"BIPIA EmailQA clean baseline #{index}",
                "scenario": "email_assistant",
                "retrieved_context": sample["context"].strip(),
                "model_output": None,
            }
        )

    attack_counter = 0
    for context_index, sample in enumerate(contexts[:poison_context_limit], start=1):
        base_context = sample["context"].strip()
        question = sample["question"].strip()
        for category, prompts in attacks.items():
            attack_subtype = _slugify(category)
            for prompt_index, prompt in enumerate(prompts, start=1):
                for position in positions:
                    attack_counter += 1
                    poisoned_records.append(
                        {
                            "text": question,
                            "sample_type": "attack",
                            "attack_category": "indirect_prompt_injection",
                            "attack_subtype": attack_subtype,
                            "risk_level": "high",
                            "source": dataset_name,
                            "language": "en",
                            "source_dataset": dataset_name,
                            "source_split": source_split,
                            "original_label": "attack",
                            "mapping_rule": "bipia_emailqa_v1",
                            "import_batch": import_batch,
                            "tags": [
                                "bipia",
                                "emailqa",
                                "indirect_prompt_injection",
                                f"attack_category:{attack_subtype}",
                                f"position:{position}",
                            ],
                            "expected_result": "block",
                            "actual_result": None,
                            "reviewer": None,
                            "review_status": "pending",
                            "label_confidence": 0.99,
                            "duplicate_group_id": None,
                            "boundary_sample_flag": False,
                            "needs_review": False,
                            "review_comment": (
                                f"BIPIA EmailQA poisoned subset; context #{context_index}, "
                                f"attack #{prompt_index}, position={position}"
                            ),
                            "scenario": "email_assistant",
                            "retrieved_context": _insert_attack(base_context, prompt, position),
                            "model_output": None,
                        }
                    )
    return clean_records + poisoned_records


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
    parser = argparse.ArgumentParser(description="Download the public BIPIA EmailQA benchmark and test indirect prompt injection detection")
    parser.add_argument("--dataset-name", default=DEFAULT_DATASET_NAME)
    parser.add_argument("--context-url", default=DEFAULT_CONTEXT_URL)
    parser.add_argument("--attack-url", default=DEFAULT_ATTACK_URL)
    parser.add_argument("--tenant-slug", default="open-dataset-lab")
    parser.add_argument("--tenant-name", default="Open Dataset Lab")
    parser.add_argument("--application-key", default="bipia-email-indirect-test")
    parser.add_argument("--application-name", default="BIPIA Email Indirect Test")
    parser.add_argument("--output-csv", default=str(ROOT / "data/external/bipia_email_indirect_subset.csv"))
    parser.add_argument("--run-name", default="external_bipia_email_indirect_subset")
    parser.add_argument("--source-split", default="test")
    parser.add_argument("--import-batch", default="")
    parser.add_argument("--clean-context-limit", type=int, default=50)
    parser.add_argument("--poison-context-limit", type=int, default=5)
    parser.add_argument("--positions", default="start,end", help="Comma-separated positions: start,end,middle")
    parser.add_argument("--skip-download", action="store_true", help="Reuse an existing transformed CSV instead of downloading again")
    parser.add_argument("--disable-threshold-scan", action="store_true")
    parser.add_argument("--strategy", action="append", dest="strategies")
    args = parser.parse_args()

    strategies = args.strategies or ["rules_only", "rules_classifier", "full_stack", "context_hardened_v3"]
    import_batch = args.import_batch or datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    output_path = Path(args.output_csv)
    if args.skip_download:
        records = load_records_from_path(output_path)
    else:
        positions = [position.strip() for position in args.positions.split(",") if position.strip()]
        contexts = _load_jsonl_url(args.context_url)
        attacks = _load_json_url(args.attack_url)
        records = _build_records(
            contexts,
            attacks,
            dataset_name=args.dataset_name,
            source_split=args.source_split,
            import_batch=import_batch,
            clean_context_limit=args.clean_context_limit,
            poison_context_limit=args.poison_context_limit,
            positions=positions,
        )
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
                    "context_url": args.context_url,
                    "attack_url": args.attack_url,
                    "rows_prepared": len(records),
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

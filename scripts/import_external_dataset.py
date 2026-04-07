from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.config import get_settings
from core.database import SessionLocal
from models.entities import Application, Sample, Tenant
from services.exceptions import SampleImportError
from services.sample_importer import import_samples, load_records_from_path


def _ensure_scope(db, *, tenant_slug: str, tenant_name: str, app_key: str, app_name: str) -> tuple[Tenant, Application]:
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).one_or_none()
    if tenant is None:
        tenant = Tenant(name=tenant_name, slug=tenant_slug, description="External dataset import scope")
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
            description="External dataset import target",
        )
        db.add(application)
        db.commit()
        db.refresh(application)
    elif application.tenant_id != tenant.id:
        raise ValueError("application key already exists under another tenant")
    return tenant, application


def _read_parquet_records(path: Path) -> list[dict[str, Any]]:
    settings = get_settings()
    limit = settings.max_import_records
    try:
        import pyarrow.parquet as pq

        parquet_file = pq.ParquetFile(path)
        total_rows = parquet_file.metadata.num_rows if parquet_file.metadata is not None else None
        if total_rows is not None and total_rows > limit:
            raise SampleImportError(f"too many records in one import: parquet rows={total_rows}, limit={limit}")
        records: list[dict[str, Any]] = []
        batch_size = max(1, min(limit, 500))
        for batch in parquet_file.iter_batches(batch_size=batch_size):
            frame = batch.to_pandas()
            records.extend(frame.to_dict(orient="records"))
            if len(records) > limit:
                raise SampleImportError(f"too many records in one import: parquet rows>{limit}")
        return records
    except ImportError:
        dataframe = pd.read_parquet(path)
        if len(dataframe) > limit:
            raise SampleImportError(f"too many records in one import: parquet rows={len(dataframe)}, limit={limit}")
        return dataframe.to_dict(orient="records")


def _read_records(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".parquet":
        return _read_parquet_records(path)
    return load_records_from_path(path)


def _stringify_tags(*parts: str | None) -> list[str]:
    return [part for part in parts if part]


def _infer_language(text: str) -> str:
    return "zh" if any("\u4e00" <= char <= "\u9fff" for char in text) else "en"


def _map_unified_prompt_guard(
    row: dict[str, Any],
    *,
    dataset_name: str,
    split: str,
    import_batch: str,
) -> dict[str, Any]:
    text = str(row.get("text") or row.get("prompt") or "").strip()
    if not text:
        raise ValueError("missing text")
    label = str(row.get("label") or "").strip().lower()
    source = str(row.get("source") or "upg").strip().lower()
    lang = str(row.get("lang") or "").strip().lower() or _infer_language(text)
    malicious = label in {"unsafe", "1", "true", "malicious", "attack"}
    aug_type = str(row.get("aug_type") or "").strip().lower()
    category, subtype = _map_upg_attack_taxonomy(source=source, aug_type=aug_type, malicious=malicious)
    return {
        "text": text,
        "sample_type": "attack" if malicious else "benign",
        "attack_category": category,
        "attack_subtype": subtype,
        "risk_level": "high" if malicious else "low",
        "source": dataset_name,
        "language": lang,
        "source_dataset": dataset_name,
        "source_split": split,
        "original_label": label or None,
        "mapping_rule": "unified_prompt_guard_v2",
        "import_batch": import_batch,
        "tags": _stringify_tags(
            "external_source",
            f"language:{lang}",
            f"upg_source:{source}" if source else None,
            f"aug_type:{row.get('aug_type')}" if row.get("aug_type") else None,
        ),
        "expected_result": "block" if malicious else "allow",
        "actual_result": None,
        "reviewer": None,
        "review_status": "pending",
        "label_confidence": 0.95,
        "duplicate_group_id": None,
        "boundary_sample_flag": False,
        "needs_review": False,
        "review_comment": f"Imported from {dataset_name}:{split} using unified_prompt_guard_v2",
        "scenario": "general_assistant",
        "retrieved_context": None,
        "model_output": None,
    }


def _map_upg_attack_taxonomy(*, source: str, aug_type: str, malicious: bool) -> tuple[str | None, str | None]:
    if not malicious:
        return None, None
    normalized = " ".join(part for part in [source, aug_type] if part).lower()
    jailbreak_markers = ("jailbreak", "越狱", "roleplay", "dan", "prompt injection", "prompt_injection")
    if any(marker in normalized for marker in jailbreak_markers):
        return "jailbreak", source or aug_type or "unified_prompt_guard"
    return "unsafe_prompt", source or aug_type or "unified_prompt_guard"


def _pick(row: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in {None, ""}:
            return row[key]
    return None


def _map_strata_sword(
    row: dict[str, Any],
    *,
    dataset_name: str,
    split: str,
    import_batch: str,
) -> dict[str, Any]:
    text = str(_pick(row, "prompt", "text", "query", "instruction") or "").strip()
    if not text:
        raise ValueError("missing prompt/text")
    language = str(_pick(row, "language", "lang") or _infer_language(text)).strip().lower()
    attack_method = str(_pick(row, "attack_method", "attack_type", "method", "jailbreak_method") or "strata_sword").strip()
    tier = str(_pick(row, "tier", "level", "complexity", "reasoning_level") or "unknown").strip().lower()
    return {
        "text": text,
        "sample_type": "attack",
        "attack_category": "jailbreak",
        "attack_subtype": attack_method.lower().replace(" ", "_"),
        "risk_level": "high",
        "source": dataset_name,
        "language": language,
        "source_dataset": dataset_name,
        "source_split": split,
        "original_label": str(_pick(row, "label", "type") or "attack"),
        "mapping_rule": "strata_sword_v1",
        "import_batch": import_batch,
        "tags": _stringify_tags(
            "external_source",
            f"language:{language}",
            f"attack_method:{attack_method.lower().replace(' ', '_')}",
            f"tier:{tier}",
        ),
        "expected_result": "block",
        "actual_result": None,
        "reviewer": None,
        "review_status": "pending",
        "label_confidence": 0.97,
        "duplicate_group_id": None,
        "boundary_sample_flag": False,
        "needs_review": False,
        "review_comment": f"Imported from {dataset_name}:{split} using strata_sword_v1",
        "scenario": "general_assistant",
        "retrieved_context": None,
        "model_output": None,
    }


def _map_records(
    records: list[dict[str, Any]],
    *,
    dataset_type: str,
    dataset_name: str,
    split: str,
    import_batch: str,
) -> list[dict[str, Any]]:
    mapper = {
        "unified-prompt-guard": _map_unified_prompt_guard,
        "strata-sword": _map_strata_sword,
    }[dataset_type]
    mapped: list[dict[str, Any]] = []
    skipped = 0
    for row in records:
        try:
            mapped.append(mapper(row, dataset_name=dataset_name, split=split, import_batch=import_batch))
        except ValueError:
            skipped += 1
    if not mapped:
        raise ValueError("no records could be mapped from source file")
    if skipped:
        print(json.dumps({"mapping_skipped": skipped}, ensure_ascii=False))
    return mapped


def main() -> None:
    parser = argparse.ArgumentParser(description="Import an external benchmark dataset into tenant-scoped samples")
    parser.add_argument("--dataset-type", choices=["unified-prompt-guard", "strata-sword"], required=True)
    parser.add_argument("--input", required=True, help="Path to source file: parquet/csv/jsonl")
    parser.add_argument("--dataset-name", required=True, help="Human-readable dataset identifier")
    parser.add_argument("--source-split", default="test")
    parser.add_argument("--tenant-slug", default="external-dataset-lab")
    parser.add_argument("--tenant-name", default="External Dataset Lab")
    parser.add_argument("--application-key", required=True)
    parser.add_argument("--application-name", required=True)
    parser.add_argument("--import-batch", default="")
    args = parser.parse_args()

    import_batch = args.import_batch or datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    source_path = Path(args.input)
    try:
        records = _read_records(source_path)
        mapped_records = _map_records(
            records,
            dataset_type=args.dataset_type,
            dataset_name=args.dataset_name,
            split=args.source_split,
            import_batch=import_batch,
        )
    except (SampleImportError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

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
            mapped_records,
            source=source_path.name,
            tenant_id=tenant.id,
            application_id=application.id,
        )
        total_scoped = (
            db.query(Sample)
            .filter(Sample.tenant_id == tenant.id, Sample.application_id == application.id)
            .count()
        )
        print(
            json.dumps(
                {
                    "dataset_type": args.dataset_type,
                    "dataset_name": args.dataset_name,
                    "source_split": args.source_split,
                    "input": str(source_path),
                    "mapped_records": len(mapped_records),
                    "imported": imported,
                    "skipped": skipped,
                    "tenant_slug": tenant.slug,
                    "application_key": application.app_key,
                    "import_batch": import_batch,
                    "scoped_sample_count": total_scoped,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()

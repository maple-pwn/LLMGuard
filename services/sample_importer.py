from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from core.config import get_settings
from sqlalchemy.orm import Session

from models.entities import Sample
from services.exceptions import SampleImportError


def _parse_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []
        if value.startswith("["):
            parsed = json.loads(value)
            return [str(item) for item in parsed]
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(value)]


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value in {None, ""}:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def load_records_from_text(content: str, file_suffix: str) -> list[dict[str, Any]]:
    settings = get_settings()
    if file_suffix.lower() == ".jsonl":
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SampleImportError(f"invalid jsonl at line {line_number}") from exc
            if not isinstance(payload, dict):
                raise SampleImportError(f"invalid record at line {line_number}")
            records.append(payload)
            if len(records) > settings.max_import_records:
                raise SampleImportError("too many records in one import")
        return records
    if file_suffix.lower() == ".csv":
        try:
            reader = csv.DictReader(io.StringIO(content))
            records = [dict(row) for row in reader]
        except csv.Error as exc:
            raise SampleImportError("invalid csv content") from exc
        if len(records) > settings.max_import_records:
            raise SampleImportError("too many records in one import")
        return records
    raise SampleImportError("仅支持 JSONL 或 CSV")


def load_records_from_path(path: str | Path) -> list[dict[str, Any]]:
    resolved = Path(path)
    return load_records_from_text(resolved.read_text(encoding="utf-8"), resolved.suffix)


def normalize_sample_payload(record: dict[str, Any], default_source: str | None = None) -> dict[str, Any]:
    text = str(record.get("text") or record.get("user_input") or "").strip()
    if not text:
        raise SampleImportError("sample text is empty")
    return {
        "text": text,
        "sample_type": str(record.get("sample_type", "benign")),
        "attack_category": record.get("attack_category"),
        "attack_subtype": record.get("attack_subtype"),
        "risk_level": record.get("risk_level"),
        "source": record.get("source") or default_source,
        "tags": _parse_tags(record.get("tags")),
        "expected_result": str(record.get("expected_result", "allow")),
        "actual_result": record.get("actual_result"),
        "reviewer": record.get("reviewer"),
        "review_status": str(record.get("review_status", "pending")),
        "label_confidence": float(record["label_confidence"]) if record.get("label_confidence") not in {None, ""} else None,
        "duplicate_group_id": record.get("duplicate_group_id"),
        "boundary_sample_flag": _parse_bool(record.get("boundary_sample_flag", False)),
        "needs_review": _parse_bool(record.get("needs_review", False)),
        "review_comment": record.get("review_comment"),
        "scenario": record.get("scenario"),
        "retrieved_context": record.get("retrieved_context"),
        "model_output": record.get("model_output"),
    }


def import_samples(
    db: Session,
    records: list[dict[str, Any]],
    source: str,
    *,
    tenant_id: int | None = None,
    application_id: int | None = None,
) -> tuple[int, int]:
    imported = 0
    skipped = 0
    for record in records:
        try:
            payload = normalize_sample_payload(record, default_source=source)
        except SampleImportError:
            skipped += 1
            continue
        existing = (
            db.query(Sample)
            .filter(
                Sample.text == payload["text"],
                Sample.sample_type == payload["sample_type"],
                Sample.tenant_id == tenant_id,
                Sample.application_id == application_id,
            )
            .one_or_none()
        )
        if existing is not None:
            skipped += 1
            continue
        db.add(Sample(tenant_id=tenant_id, application_id=application_id, **payload))
        imported += 1
    db.commit()
    return imported, skipped

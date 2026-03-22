from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from core.privacy import fingerprint_text, sanitize_for_storage
from core.security import AuthContext
from models.entities import AuditLog


def record_audit_event(
    db: Session,
    *,
    actor: AuthContext | None,
    event_type: str,
    object_type: str,
    object_id: str | int | None = None,
    tenant_id: int | None = None,
    application_id: int | None = None,
    environment: str | None = None,
    payload: dict[str, Any] | None = None,
) -> AuditLog:
    normalized_payload = payload or {}
    payload_repr = repr(sorted(normalized_payload.items()))
    immutable_basis = f"{event_type}|{object_type}|{object_id}|{tenant_id}|{application_id}|{payload_repr}"
    entry = AuditLog(
        actor_user_id=actor.user.id if actor else None,
        tenant_id=tenant_id,
        application_id=application_id,
        environment=environment,
        event_type=event_type,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        request_hash=fingerprint_text(payload_repr),
        request_preview=sanitize_for_storage(payload_repr),
        event_payload=normalized_payload,
        immutable_hash=fingerprint_text(immutable_basis),
    )
    db.add(entry)
    return entry

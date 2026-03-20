from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from core.config import get_settings, has_secure_api_keys, has_secure_jwt_secret
from core.database import get_db
from models.entities import Membership, Permission, Role, RolePermission, Tenant, User


def _verify_api_key(provided_key: str | None, expected_key: str, detail: str) -> None:
    if not provided_key or not secrets.compare_digest(provided_key, expected_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


def ensure_secure_api_keys() -> None:
    settings = get_settings()
    if not has_secure_api_keys(settings):
        raise RuntimeError("SCAN_API_KEY and ADMIN_API_KEY must be explicitly configured and must not use placeholder values")


def ensure_secure_jwt() -> None:
    settings = get_settings()
    if not has_secure_jwt_secret(settings):
        raise RuntimeError("JWT_SECRET_KEY must be explicitly configured and must not use placeholder values")


def require_scan_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    settings = get_settings()
    if not has_secure_api_keys(settings):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="server auth is not configured")
    _verify_api_key(x_api_key, settings.scan_api_key, "invalid scan api key")


def require_admin_api_key(x_admin_key: str | None = Header(default=None, alias="X-Admin-Key")) -> None:
    settings = get_settings()
    if not has_secure_api_keys(settings):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="server auth is not configured")
    _verify_api_key(x_admin_key, settings.admin_api_key, "invalid admin api key")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _jwt_secret_bytes() -> bytes:
    settings = get_settings()
    if not has_secure_jwt_secret(settings):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="server jwt auth is not configured")
    return settings.jwt_secret_key.encode("utf-8")


def create_access_token(*, subject: str, user_id: int, expires_minutes: int | None = None) -> str:
    settings = get_settings()
    ttl = expires_minutes or settings.access_token_expire_minutes
    now = datetime.now(UTC)
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "uid": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ttl)).timestamp()),
    }
    header_part = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("utf-8")
    signature = hmac.new(_jwt_secret_bytes(), signing_input, hashlib.sha256).digest()
    return f"{header_part}.{payload_part}.{_b64url_encode(signature)}"


def decode_access_token(token: str) -> dict:
    try:
        header_part, payload_part, signature_part = token.split(".")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid access token") from exc
    signing_input = f"{header_part}.{payload_part}".encode("utf-8")
    expected_signature = hmac.new(_jwt_secret_bytes(), signing_input, hashlib.sha256).digest()
    provided_signature = _b64url_decode(signature_part)
    if not hmac.compare_digest(expected_signature, provided_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid access token signature")
    try:
        payload = json.loads(_b64url_decode(payload_part))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid access token payload") from exc
    if int(payload.get("exp", 0)) < int(datetime.now(UTC).timestamp()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="access token expired")
    return payload


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return f"pbkdf2_sha256${_b64url_encode(salt)}${_b64url_encode(derived)}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, salt_raw, digest_raw = password_hash.split("$", 2)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    salt = _b64url_decode(salt_raw)
    expected = _b64url_decode(digest_raw)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return hmac.compare_digest(derived, expected)


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    user = db.query(User).filter(User.email == email, User.is_active.is_(True)).one_or_none()
    if user is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


@dataclass
class AuthContext:
    user: User
    memberships: list[Membership]
    tenant_ids: set[int]
    tenant_permissions: dict[int, set[str]]

    @property
    def is_superuser(self) -> bool:
        return self.user.is_superuser

    @property
    def permissions(self) -> set[str]:
        if self.is_superuser:
            return set()
        return {permission for permissions in self.tenant_permissions.values() for permission in permissions}

    def has_permission(self, permission: str, tenant_id: int | None = None) -> bool:
        if self.is_superuser:
            return True
        if tenant_id is None:
            return any(permission in permissions for permissions in self.tenant_permissions.values())
        return permission in self.tenant_permissions.get(tenant_id, set())

    def can_access_tenant(self, tenant_id: int | None) -> bool:
        if self.is_superuser:
            return True
        if tenant_id is None:
            return False
        return tenant_id in self.tenant_ids

    def visible_tenant_ids(self, permission: str | None = None) -> set[int]:
        if self.is_superuser:
            return self.tenant_ids
        if permission is None:
            return self.tenant_ids
        return {tenant_id for tenant_id, permissions in self.tenant_permissions.items() if permission in permissions}


http_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> AuthContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    payload = decode_access_token(credentials.credentials)
    user = db.query(User).filter(User.id == int(payload["uid"]), User.is_active.is_(True)).one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user not found or inactive")
    memberships = db.query(Membership).filter(Membership.user_id == user.id).all()
    tenant_ids = {membership.tenant_id for membership in memberships}
    tenant_permissions: dict[int, set[str]] = {}
    if memberships:
        rows = (
            db.query(Membership.tenant_id, Permission.name)
            .join(Role, Role.id == Membership.role_id)
            .join(RolePermission, RolePermission.role_id == Role.id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .filter(Membership.user_id == user.id)
            .all()
        )
        for tenant_id, permission_name in rows:
            tenant_permissions.setdefault(int(tenant_id), set()).add(str(permission_name))
    return AuthContext(user=user, memberships=memberships, tenant_ids=tenant_ids, tenant_permissions=tenant_permissions)


def require_permission(permission: str):
    def dependency(actor: AuthContext = Depends(get_current_user)) -> AuthContext:
        if not actor.has_permission(permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"missing permission: {permission}")
        return actor

    return dependency


def require_superuser(actor: AuthContext = Depends(get_current_user)) -> AuthContext:
    if not actor.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="superuser required")
    return actor


def ensure_actor_has_tenant_permission(actor: AuthContext, tenant_id: int | None, permission: str) -> None:
    if actor.is_superuser:
        return
    if tenant_id is None or not actor.has_permission(permission, tenant_id=tenant_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"missing permission: {permission}")


def ensure_actor_can_access_tenant(actor: AuthContext, tenant_id: int | None) -> None:
    if not actor.can_access_tenant(tenant_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant access denied")


def resolve_actor_tenant(db: Session, actor: AuthContext, tenant_slug: str | None) -> Tenant | None:
    if tenant_slug is None:
        return None
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).one_or_none()
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    ensure_actor_can_access_tenant(actor, tenant.id)
    return tenant

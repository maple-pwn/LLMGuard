from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from core.config import get_settings
from core.database import get_db
from core.security import (
    AuthContext,
    authenticate_user,
    create_access_token,
    get_current_user,
    hash_password,
    require_admin_api_key,
)
from models.entities import User
from models.schemas import CurrentUserMembershipRead, CurrentUserRead, LoginRequest, TokenResponse, UserCreate, UserRead


router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/bootstrap-admin", response_model=UserRead)
def bootstrap_admin(
    payload: UserCreate,
    _: None = Depends(require_admin_api_key),
    db: Session = Depends(get_db),
) -> User:
    if db.query(User.id).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="bootstrap admin already exists")
    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        is_active=True,
        is_superuser=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = authenticate_user(db, payload.email.lower(), payload.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    settings = get_settings()
    access_token = create_access_token(subject=user.email, user_id=user.id)
    return TokenResponse(access_token=access_token, expires_in=settings.access_token_expire_minutes * 60)


@router.get("/me", response_model=CurrentUserRead)
def me(actor: AuthContext = Depends(get_current_user)) -> CurrentUserRead:
    return CurrentUserRead(
        id=actor.user.id,
        email=actor.user.email,
        full_name=actor.user.full_name,
        is_superuser=actor.user.is_superuser,
        permissions=sorted(actor.permissions),
        tenant_ids=sorted(actor.tenant_ids),
        memberships=[
            CurrentUserMembershipRead(tenant_id=membership.tenant_id, role_id=membership.role_id)
            for membership in actor.memberships
        ],
    )

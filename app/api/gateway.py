from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from core.database import get_db
from core.security import require_scan_api_key
from models.schemas import ScanRequest, ScanResponse
from services.detection import get_detection_service
from services.exceptions import PolicyBindingResolutionError


router = APIRouter(prefix="/gateway", tags=["gateway"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/scan", response_model=ScanResponse)
def scan(
    payload: ScanRequest,
    _: None = Depends(require_scan_api_key),
    db: Session = Depends(get_db),
) -> ScanResponse:
    try:
        return get_detection_service().scan(payload, db=db, persist=True)
    except PolicyBindingResolutionError as exc:
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail=str(exc)) from exc

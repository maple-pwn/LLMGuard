from __future__ import annotations

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.routes import compare_evaluations
from core.config import (
    EXAMPLE_ADMIN_API_KEY,
    EXAMPLE_SCAN_API_KEY,
    PLACEHOLDER_ADMIN_API_KEY,
    PLACEHOLDER_SCAN_API_KEY,
    get_settings,
)
from core.security import ensure_secure_api_keys, require_admin_api_key, require_scan_api_key
from models.schemas import EvaluationRequest, ScanRequest
from services.exceptions import SampleImportError
from services.sample_importer import load_records_from_text


def test_scan_requires_valid_api_key() -> None:
    with pytest.raises(HTTPException) as exc_info:
        require_scan_api_key("wrong-key")
    assert exc_info.value.status_code == 401


def test_admin_requires_valid_api_key() -> None:
    with pytest.raises(HTTPException) as exc_info:
        require_admin_api_key("wrong-key")
    assert exc_info.value.status_code == 401


def test_placeholder_keys_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCAN_API_KEY", PLACEHOLDER_SCAN_API_KEY)
    monkeypatch.setenv("ADMIN_API_KEY", PLACEHOLDER_ADMIN_API_KEY)
    get_settings.cache_clear()
    with pytest.raises(RuntimeError):
        ensure_secure_api_keys()
    monkeypatch.setenv("SCAN_API_KEY", "test-scan-key")
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key")
    get_settings.cache_clear()


def test_example_keys_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCAN_API_KEY", EXAMPLE_SCAN_API_KEY)
    monkeypatch.setenv("ADMIN_API_KEY", EXAMPLE_ADMIN_API_KEY)
    get_settings.cache_clear()
    with pytest.raises(RuntimeError):
        ensure_secure_api_keys()
    monkeypatch.setenv("SCAN_API_KEY", "test-scan-key")
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key")
    get_settings.cache_clear()


def test_import_bad_jsonl_returns_domain_error() -> None:
    with pytest.raises(SampleImportError) as exc_info:
        load_records_from_text("{bad json}\n", ".jsonl")
    assert "invalid jsonl" in str(exc_info.value)


def test_evaluate_empty_strategy_list_rejected() -> None:
    with pytest.raises(ValidationError):
        EvaluationRequest(run_name="bad-eval", strategy_names=[], enable_threshold_scan=False)


def test_evaluate_duplicate_strategy_list_rejected() -> None:
    with pytest.raises(ValidationError):
        EvaluationRequest(run_name="dup-eval", strategy_names=["rules_only", "rules_only"])


def test_compare_route_rejects_invalid_run_ids() -> None:
    with pytest.raises(HTTPException) as exc_info:
        compare_evaluations(run_ids="1,a,2", actor=None, db=None)
    assert exc_info.value.status_code == 400


def test_scan_request_uses_runtime_length_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_USER_INPUT_CHARS", "5")
    get_settings.cache_clear()
    with pytest.raises(ValidationError):
        ScanRequest(user_input="123456", scenario="general_assistant", session_id="s")
    monkeypatch.delenv("MAX_USER_INPUT_CHARS", raising=False)
    get_settings.cache_clear()


def test_evaluation_request_uses_runtime_strategy_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_STRATEGY_COUNT", "2")
    get_settings.cache_clear()
    with pytest.raises(ValidationError):
        EvaluationRequest(run_name="runtime-limit", strategy_names=["a", "b", "c"], enable_threshold_scan=False)
    monkeypatch.delenv("MAX_STRATEGY_COUNT", raising=False)
    get_settings.cache_clear()

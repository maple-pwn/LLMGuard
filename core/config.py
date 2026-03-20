from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
PLACEHOLDER_SCAN_API_KEY = "change-me-scan-key"
PLACEHOLDER_ADMIN_API_KEY = "change-me-admin-key"
PLACEHOLDER_JWT_SECRET = "change-me-jwt-secret"
EXAMPLE_SCAN_API_KEY = "replace-with-real-scan-key"
EXAMPLE_ADMIN_API_KEY = "replace-with-real-admin-key"
_INSECURE_API_KEY_VALUES = {
    "",
    PLACEHOLDER_SCAN_API_KEY,
    PLACEHOLDER_ADMIN_API_KEY,
    EXAMPLE_SCAN_API_KEY,
    EXAMPLE_ADMIN_API_KEY,
}
_INSECURE_API_KEY_MARKERS = (
    "change-me",
    "replace-with-real",
    "placeholder",
    "example",
    "your-",
)


@dataclass(frozen=True)
class Settings:
    app_name: str = field(default_factory=lambda: os.getenv("APP_NAME", "LLM Firewall Evaluation System"))
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./data/llm_firewall.db"))
    jwt_secret_key: str = field(default_factory=lambda: os.getenv("JWT_SECRET_KEY", PLACEHOLDER_JWT_SECRET))
    access_token_expire_minutes: int = field(default_factory=lambda: int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")))
    task_queue_backend: str = field(default_factory=lambda: os.getenv("TASK_QUEUE_BACKEND", "database"))
    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    task_queue_name: str = field(default_factory=lambda: os.getenv("TASK_QUEUE_NAME", "llm_firewall_tasks"))
    task_timeout_seconds: int = field(default_factory=lambda: int(os.getenv("TASK_TIMEOUT_SECONDS", "300")))
    task_max_retries: int = field(default_factory=lambda: int(os.getenv("TASK_MAX_RETRIES", "3")))
    rule_file: Path = field(default_factory=lambda: BASE_DIR / os.getenv("RULE_FILE", "data/rules/default_rules.yaml"))
    model_path: Path = field(default_factory=lambda: BASE_DIR / os.getenv("MODEL_PATH", "data/models/risk_classifier.joblib"))
    report_dir: Path = field(default_factory=lambda: BASE_DIR / os.getenv("REPORT_DIR", "docs/reports"))
    scan_api_key: str = field(default_factory=lambda: os.getenv("SCAN_API_KEY", PLACEHOLDER_SCAN_API_KEY))
    admin_api_key: str = field(default_factory=lambda: os.getenv("ADMIN_API_KEY", PLACEHOLDER_ADMIN_API_KEY))
    default_review_threshold: float = field(default_factory=lambda: float(os.getenv("DEFAULT_REVIEW_THRESHOLD", "0.55")))
    default_block_threshold: float = field(default_factory=lambda: float(os.getenv("DEFAULT_BLOCK_THRESHOLD", "0.80")))
    max_user_input_chars: int = field(default_factory=lambda: int(os.getenv("MAX_USER_INPUT_CHARS", "4000")))
    max_context_chars: int = field(default_factory=lambda: int(os.getenv("MAX_CONTEXT_CHARS", "8000")))
    max_model_output_chars: int = field(default_factory=lambda: int(os.getenv("MAX_MODEL_OUTPUT_CHARS", "8000")))
    max_upload_bytes: int = field(default_factory=lambda: int(os.getenv("MAX_UPLOAD_BYTES", "1048576")))
    max_import_records: int = field(default_factory=lambda: int(os.getenv("MAX_IMPORT_RECORDS", "1000")))
    max_eval_samples: int = field(default_factory=lambda: int(os.getenv("MAX_EVAL_SAMPLES", "300")))
    max_strategy_count: int = field(default_factory=lambda: int(os.getenv("MAX_STRATEGY_COUNT", "8")))
    max_eval_operations: int = field(default_factory=lambda: int(os.getenv("MAX_EVAL_OPERATIONS", "15000")))
    max_sample_audit_samples: int = field(default_factory=lambda: int(os.getenv("MAX_SAMPLE_AUDIT_SAMPLES", "400")))
    max_sample_audit_pairs: int = field(default_factory=lambda: int(os.getenv("MAX_SAMPLE_AUDIT_PAIRS", "20000")))
    storage_preview_chars: int = field(default_factory=lambda: int(os.getenv("STORAGE_PREVIEW_CHARS", "512")))
    persist_model_output: bool = field(default_factory=lambda: os.getenv("PERSIST_MODEL_OUTPUT", "false").lower() == "true")
    model_sha256: str | None = field(default_factory=lambda: os.getenv("MODEL_SHA256") or None)
    max_rule_count: int = field(default_factory=lambda: int(os.getenv("MAX_RULE_COUNT", "256")))
    max_rule_pattern_chars: int = field(default_factory=lambda: int(os.getenv("MAX_RULE_PATTERN_CHARS", "300")))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    @property
    def data_dir(self) -> Path:
        return BASE_DIR / "data"

    @property
    def sample_dir(self) -> Path:
        return self.data_dir / "samples"

    @property
    def model_dir(self) -> Path:
        return self.data_dir / "models"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def has_secure_api_keys(settings: Settings) -> bool:
    return is_secure_api_key(settings.scan_api_key) and is_secure_api_key(settings.admin_api_key)


def is_secure_api_key(value: str) -> bool:
    normalized = value.strip()
    lowered = normalized.lower()
    if len(normalized) < 12:
        return False
    if lowered in _INSECURE_API_KEY_VALUES:
        return False
    return not any(marker in lowered for marker in _INSECURE_API_KEY_MARKERS)


def has_secure_jwt_secret(settings: Settings) -> bool:
    value = settings.jwt_secret_key.strip().lower()
    return len(value) >= 16 and value != PLACEHOLDER_JWT_SECRET and not any(marker in value for marker in _INSECURE_API_KEY_MARKERS)

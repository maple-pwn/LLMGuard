from __future__ import annotations

import hashlib
import re

from core.config import get_settings


_SECRET_PATTERNS = [
    re.compile(r"(?i)(token|api[_-]?key|password|passwd|secret|cookie)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\b(sk-[A-Za-z0-9_-]{6,}|AKIA[0-9A-Z]{8,}|AIza[0-9A-Za-z_-]{10,})\b"),
]


def sanitize_for_storage(text: str | None) -> str | None:
    if not text:
        return text
    sanitized = text
    for pattern in _SECRET_PATTERNS:
        sanitized = pattern.sub(lambda match: _mask_match(match), sanitized)
    max_len = get_settings().storage_preview_chars
    if len(sanitized) > max_len:
        return f"{sanitized[:max_len]}...[truncated]"
    return sanitized


def fingerprint_text(text: str | None) -> str | None:
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _mask_match(match: re.Match[str]) -> str:
    if match.lastindex and match.lastindex >= 2:
        return f"{match.group(1)}=[REDACTED]"
    return "[REDACTED_SECRET]"

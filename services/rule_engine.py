from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from core.config import get_settings
from models.entities import Rule


@dataclass
class RuleDefinition:
    rule_id: str
    name: str
    description: str
    pattern: str
    severity: str
    enabled: bool
    weight: float
    category: str
    rule_version: str
    created_by: str
    targets: list[str]
    explanation: str
    change_note: str
    regex: re.Pattern[str]


@dataclass
class RuleMatch:
    rule_id: str
    name: str
    category: str
    severity: str
    weight: float
    target: str
    matched_text: str
    explanation: str


class RuleEngine:
    def __init__(self, rule_file: Path | None = None) -> None:
        settings = get_settings()
        self.rule_file = rule_file or settings.rule_file
        self.rules: list[RuleDefinition] = []
        if self.rule_file.exists():
            self.reload_rules()

    def reload_rules(self, db: Session | None = None) -> int:
        settings = get_settings()
        payload = yaml.safe_load(self.rule_file.read_text(encoding="utf-8")) if self.rule_file.exists() else {"rules": []}
        raw_rules = payload["rules"] if isinstance(payload, dict) else payload
        if not isinstance(raw_rules, list):
            raise ValueError("rule file must contain a list of rules")
        if len(raw_rules) > settings.max_rule_count:
            raise ValueError(f"too many rules: {len(raw_rules)} > {settings.max_rule_count}")
        compiled_rules: list[RuleDefinition] = []
        for item in raw_rules:
            self._validate_rule_item(item, settings.max_rule_pattern_chars)
            flags = re.MULTILINE
            if item.get("case_insensitive", True):
                flags |= re.IGNORECASE
            if item.get("dotall", True):
                flags |= re.DOTALL
            try:
                regex = re.compile(item["pattern"], flags)
            except re.error as exc:
                raise ValueError(f"invalid regex in rule {item['rule_id']}: {exc}") from exc
            compiled_rules.append(
                RuleDefinition(
                    rule_id=item["rule_id"],
                    name=item["name"],
                    description=item.get("description", ""),
                    pattern=item["pattern"],
                    severity=item.get("severity", "medium"),
                    enabled=item.get("enabled", True),
                    weight=float(item.get("weight", 0.5)),
                    category=item.get("category", "unknown"),
                    rule_version=item.get("rule_version", "v1"),
                    created_by=item.get("created_by", "security_ops"),
                    targets=item.get("targets", ["user_input"]),
                    explanation=item.get("explanation", item.get("description", "")),
                    change_note=item.get("change_note", ""),
                    regex=regex,
                )
            )
        self.rules = compiled_rules
        if db is not None:
            self._sync_to_db(db)
        return len(compiled_rules)

    def _validate_rule_item(self, item: dict[str, Any], max_pattern_chars: int) -> None:
        required_fields = {"rule_id", "name", "pattern"}
        missing = [field for field in required_fields if not item.get(field)]
        if missing:
            raise ValueError(f"rule missing required fields: {','.join(missing)}")
        if len(str(item["pattern"])) > max_pattern_chars:
            raise ValueError(f"rule {item['rule_id']} pattern is too long")
        targets = item.get("targets", ["user_input"])
        allowed_targets = {"user_input", "retrieved_context", "model_output"}
        if not set(targets).issubset(allowed_targets):
            raise ValueError(f"rule {item['rule_id']} contains invalid targets")

    def _sync_to_db(self, db: Session) -> None:
        db.query(Rule).delete()
        for rule in self.rules:
            db.add(
                Rule(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    pattern=rule.pattern,
                    severity=rule.severity,
                    enabled=rule.enabled,
                    weight=rule.weight,
                    category=rule.category,
                    rule_version=rule.rule_version,
                    created_by=rule.created_by,
                    targets=rule.targets,
                    explanation=rule.explanation,
                    source_file=str(self.rule_file),
                    change_note=rule.change_note,
                    updated_at=datetime.utcnow(),
                )
            )
        db.commit()

    def scan_fields(self, fields: dict[str, str | None]) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            for target in rule.targets:
                content = fields.get(target) or ""
                if not content:
                    continue
                match = rule.regex.search(content)
                if not match:
                    continue
                excerpt = match.group(0).strip().replace("\n", " ")[:100]
                matches.append(
                    RuleMatch(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        weight=rule.weight,
                        target=target,
                        matched_text=excerpt,
                        explanation=rule.explanation,
                    )
                )
        return matches

    def export_rules(self) -> list[dict[str, Any]]:
        return [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "pattern": rule.pattern,
                "severity": rule.severity,
                "enabled": rule.enabled,
                "weight": rule.weight,
                "category": rule.category,
                "rule_version": rule.rule_version,
                "created_by": rule.created_by,
                "targets": rule.targets,
                "explanation": rule.explanation,
                "change_note": rule.change_note,
            }
            for rule in self.rules
        ]


_ENGINE: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = RuleEngine()
    return _ENGINE

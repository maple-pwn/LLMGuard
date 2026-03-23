from __future__ import annotations

from pathlib import Path

from services.rule_engine import RuleEngine


def test_rule_engine_matches_context_rule(tmp_path: Path) -> None:
    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text(
        """
rules:
  - rule_id: T001
    name: hidden
    pattern: "隐藏指令"
    severity: critical
    enabled: true
    weight: 0.9
    category: indirect_prompt_injection
    targets: ["retrieved_context"]
    explanation: "context attack"
""".strip(),
        encoding="utf-8",
    )
    engine = RuleEngine(rule_file=rule_file)
    matches = engine.scan_fields({"user_input": "正常问题", "retrieved_context": "这段文档里包含隐藏指令"})
    assert len(matches) == 1
    assert matches[0].target == "retrieved_context"
    assert matches[0].category == "indirect_prompt_injection"

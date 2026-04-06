# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - Current

### Added
- JWT login, bootstrap admin flow, RBAC, memberships, and tenant-scoped admin/ops access.
- Audit logs with actor attribution and tenant/application context.
- Policy binding resolution for `tenant + application + environment + scenario`.

### Changed
- Gateway requests now fail closed when no enabled policy binding matches.
- Admin and ops capabilities are split from the original single-admin flow.

## [0.3.0] - Platform Foundation

### Added
- `gateway / ops / admin` route split for online protection and offline operations.
- Async task execution with database queue and optional Redis + Arq backend.
- `TaskRun`, `ReviewTask`, `AlertEvent`, and `PolicyBinding` data models.
- Alembic baseline migration and PostgreSQL-friendly configuration.

### Changed
- Heavy operations such as evaluation, audits, and report generation moved to worker execution.
- Audit storage now keeps previews and hashes instead of raw full-text payloads by default.

## [0.2.0] - Ops Expansion

### Added
- Sample audit for duplicates, boundary cases, label conflicts, and review suggestions.
- Rule effectiveness analysis, casebook generation, strategy comparison, weekly reports, and postmortems.
- Streamlit views for overview, review queue, rule analysis, case center, comparison, and reports.

### Changed
- Project scope expanded from detection demo to LLM security operations workflow.

## [0.1.0] - Initial Detection Baseline

### Added
- FastAPI scan API and Streamlit demo UI.
- YAML-based rule engine with configurable targets and weights.
- Baseline classifier using TF-IDF + Logistic Regression with heuristic fallback.
- Sample import, evaluation, attribution, and Markdown report generation scripts.
- Initial SQLite schema for samples, rules, strategies, evaluations, and detections.

### Notes
- This version established the end-to-end path from sample ingestion to detection and reporting.

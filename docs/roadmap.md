# Roadmap

This roadmap focuses on small, real follow-up changes that can be developed and committed incrementally.

## Near-Term Work

### 1. Add `.env` loading and startup validation examples
- Goal: reduce local setup friction and make security configuration clearer.
- Suggested change: add `python-dotenv` support or explicit startup docs plus validation examples.

### 2. Introduce rule test fixtures by attack category
- Goal: make rule regressions easier to catch.
- Suggested change: split test samples into direct injection, indirect injection, jailbreak, and output leakage fixture groups.

### 3. Add per-rule hit counters to reports
- Goal: make rule tuning more data-driven.
- Suggested change: expose top rules by hit count, false positive contribution, and block contribution in generated reports.

### 4. Add task retry and failure demo scenarios
- Goal: improve platform credibility around async execution.
- Suggested change: add tests and docs for timeout, retry, and worker failure recovery behavior.

### 5. Add scenario-specific strategy presets
- Goal: better reflect different business risk tolerances.
- Suggested change: define clearer presets for office assistant, knowledge base QA, code assistant, and agent/tool use flows.

### 6. Add lightweight API examples collection
- Goal: make the repository easier to evaluate quickly.
- Suggested change: add `curl` or HTTP client examples for login, sample import, policy binding, scan, and report retrieval.

### 7. Add report index page in Streamlit
- Goal: improve usability of generated artifacts.
- Suggested change: provide filters for report type, run id, tenant, and generation time.

### 8. Add calibration-focused evaluation output
- Goal: improve threshold decisions beyond a single F1 comparison.
- Suggested change: export precision-recall snapshots, confusion summaries, and recommendation notes per strategy.

## Principles

- Prefer changes that improve evaluation quality, explainability, or repeatability.
- Keep each iteration independently testable.
- Avoid adding heavy dependencies unless they directly improve ops workflows.

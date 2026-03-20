PYTHON ?= .venv/bin/python

.PHONY: init run ui test seed eval train scan audit rule-report cases weekly postmortem compare worker migrate

init:
	python3 -m venv .venv
	$(PYTHON) scripts/init_db.py
	$(PYTHON) scripts/seed_data.py
	$(PYTHON) scripts/train_classifier.py

run:
	$(PYTHON) -m uvicorn app.main:app --reload

worker:
	$(PYTHON) scripts/run_worker.py

migrate:
	$(PYTHON) -m alembic upgrade head

ui:
	$(PYTHON) -m streamlit run app/ui.py

test:
	$(PYTHON) -m pytest -q

seed:
	$(PYTHON) scripts/seed_data.py

train:
	$(PYTHON) scripts/train_classifier.py

eval:
	$(PYTHON) scripts/run_evaluation.py --strategy full_stack

scan:
	$(PYTHON) scripts/demo_scan.py

audit:
	$(PYTHON) scripts/audit_samples.py

rule-report:
	$(PYTHON) scripts/analyze_rule_effectiveness.py

cases:
	$(PYTHON) scripts/build_casebook.py

weekly:
	$(PYTHON) scripts/generate_weekly_report.py

postmortem:
	$(PYTHON) scripts/generate_postmortem.py

compare:
	$(PYTHON) scripts/compare_strategies.py --run-id 6

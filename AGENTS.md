# Repository Guidelines

## 项目结构与模块组织
`app/` 包含 FastAPI 入口 `app/main.py`、`app/api/` 下的路由，以及 Streamlit 管理界面 `app/ui.py`。`core/` 放置配置、日志、数据库、迁移、启动引导和安全相关基础设施。`services/` 承载核心业务逻辑，`models/` 定义 SQLAlchemy 模型与数据结构。运维和数据处理脚本放在 `scripts/`，例如 `init_db.py`、`run_worker.py`、报告生成脚本。测试集中在 `tests/`，文件命名为 `test_*.py`。运行时数据和生成产物主要位于 `data/` 与 `docs/`。

## 构建、测试与开发命令
先执行 `python3 -m venv .venv`，再用 `.venv/bin/python -m pip install -r requirements.txt` 安装依赖。`make init` 用于初始化数据库、导入种子样本并训练基线分类器。`make run` 启动 API，`make worker` 启动异步任务 worker，`make ui` 启动 Streamlit 管理界面。数据库迁移使用 `make migrate`。本地校验常用 `make test`、`make eval` 和 `make scan`。

## 代码风格与命名约定
遵循现有 Python 风格：4 空格缩进，函数与模块使用 `snake_case`，类名使用 `PascalCase`，新增代码尽量补充明确的类型标注。模块职责保持单一：路由放在 `app/api/`，业务编排放在 `services/`，公共基础设施放在 `core/`。优先编写小而可组合的函数，配置统一通过 `core.config.get_settings()` 读取，不要硬编码路径或密钥。仓库未提供独立的格式化或 lint 配置，提交前请保持与周边代码风格一致。

## 测试规范
项目使用 `pytest`，共享夹具定义在 `tests/conftest.py`。修改功能时同步补充或更新测试，尤其关注检测规则、认证与 RBAC、任务队列执行、报表生成等路径。测试文件命名为 `test_<feature>.py`，测试函数名应直接描述行为，例如 `test_gateway_rejects_invalid_api_key`。提交前执行 `make test`；当前仓库没有覆盖率门槛，因此至少覆盖本次改动涉及的关键路径。

## 提交与 Pull Request 规范
当前工作区不包含 `.git` 历史，因此无法从本地直接归纳既有提交风格。建议使用简洁的祈使句提交标题，例如 `Add tenant-scoped ops filter`。每个提交应尽量聚焦单一变更，并把相关的 schema、脚本和测试一起提交。Pull Request 需要说明用户可见行为变化、列出配置项或迁移步骤、关联 issue；如果修改了 `app/ui.py`，附上界面截图。

## 安全与配置提示
必须为 `SCAN_API_KEY`、`ADMIN_API_KEY` 和 `JWT_SECRET_KEY` 提供真实值，应用会拒绝使用占位密钥启动。`DATABASE_URL`、`REDIS_URL` 及任务队列参数应通过环境变量配置。除非明确要更新种子数据或发布文档，不要提交本地 SQLite 数据库、训练产物或自动生成的 Markdown 报告。

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib.util import find_spec
from urllib.parse import urlparse

from core.config import get_settings


ARQ_TASK_FUNCTION = "process_platform_task"


@dataclass(frozen=True)
class QueueInfo:
    backend: str
    queue_name: str
    redis_url: str
    timeout_seconds: int
    max_retries: int


def get_queue_info() -> QueueInfo:
    settings = get_settings()
    return QueueInfo(
        backend=settings.task_queue_backend.lower(),
        queue_name=settings.task_queue_name,
        redis_url=settings.redis_url,
        timeout_seconds=settings.task_timeout_seconds,
        max_retries=settings.task_max_retries,
    )


def is_arq_backend() -> bool:
    return get_queue_info().backend == "arq"


def arq_available() -> bool:
    return find_spec("arq") is not None


def ensure_arq_available() -> None:
    if not arq_available():
        raise RuntimeError("task queue backend is set to 'arq' but package 'arq' is not installed")


def _build_redis_settings():
    ensure_arq_available()
    from arq.connections import RedisSettings

    parsed = urlparse(get_queue_info().redis_url)
    database = 0
    if parsed.path and parsed.path != "/":
        database = int(parsed.path.lstrip("/"))
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        database=database,
        password=parsed.password,
        username=parsed.username,
        ssl=parsed.scheme == "rediss",
    )


async def enqueue_arq_task_message(task_id: int, job_id: str | None = None) -> str:
    ensure_arq_available()
    from arq.connections import create_pool

    redis = await create_pool(_build_redis_settings())
    job = await redis.enqueue_job(ARQ_TASK_FUNCTION, task_id, _job_id=job_id or None)
    if job is None:
        return job_id or f"task:{task_id}"
    return job.job_id


def enqueue_arq_task_message_sync(task_id: int, job_id: str | None = None) -> str:
    return asyncio.run(enqueue_arq_task_message(task_id, job_id=job_id))


async def process_platform_task(_: dict, task_id: int) -> dict:
    from services.task_registry import execute_task_by_id

    return await asyncio.to_thread(execute_task_by_id, task_id)


class WorkerSettings:
    functions = [process_platform_task]
    queue_name = get_queue_info().queue_name
    redis_settings = _build_redis_settings() if arq_available() else None
    job_timeout = get_queue_info().timeout_seconds
    max_tries = get_queue_info().max_retries

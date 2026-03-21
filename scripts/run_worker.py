from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.bootstrap import bootstrap
from core.queue import arq_available, get_queue_info, is_arq_backend
from services.task_queue import run_one_pending_task


def main() -> None:
    parser = argparse.ArgumentParser(description="Run async ops worker")
    parser.add_argument("--once", action="store_true", help="Process at most one pending task")
    parser.add_argument("--poll-interval", type=float, default=2.0)
    args = parser.parse_args()

    bootstrap()
    if is_arq_backend():
        if args.once:
            raise SystemExit("--once is not supported when TASK_QUEUE_BACKEND=arq")
        if not arq_available():
            raise SystemExit("TASK_QUEUE_BACKEND=arq but package 'arq' is not installed")
        command = [sys.executable, "-m", "arq", "core.queue.WorkerSettings"]
        subprocess.run(command, check=True)
        return

    while True:
        task = run_one_pending_task()
        if task is not None:
            print(
                json.dumps(
                    {
                        "task_id": task.id,
                        "task_type": task.task_type,
                        "status": task.status,
                        "artifact_uri": task.artifact_uri,
                        "error": task.error_message,
                    },
                    ensure_ascii=False,
                )
            )
        if args.once:
            break
        time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()

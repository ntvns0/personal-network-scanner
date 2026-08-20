from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .insights import report_payload
from .models import HostResult
from .progress_state import ProgressState
from .scan_request import scan_request_from_payload, resolve_scan_request
from .scanner import scan_hosts


@dataclass(slots=True)
class ScanJob:
    id: str
    target: str
    status: str = "queued"
    error: str | None = None
    progress: ProgressState = field(default_factory=ProgressState)
    results: list[HostResult] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def to_dict(self) -> dict[str, Any]:
        with self.lock:
            report = report_payload(self.results) if self.status == "complete" else None
            return {
                "id": self.id,
                "target": self.target,
                "status": self.status,
                "error": self.error,
                "created_at": self.created_at,
                "completed_at": self.completed_at,
                "progress": self.progress.to_dict(),
                "report": report,
            }


class ScanStore:
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def create(self, payload: dict[str, object]) -> ScanJob:
        job = ScanJob(id=secrets.token_hex(6), target=str(payload.get("target", "local")))
        with self._lock:
            self._jobs[job.id] = job
        thread = threading.Thread(target=self._run_job, args=(job, payload), daemon=True)
        thread.start()
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[dict[str, object]]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda job: job.created_at, reverse=True)
        return [
            {
                "id": job.id,
                "target": job.target,
                "status": job.status,
                "created_at": job.created_at,
                "completed_at": job.completed_at,
            }
            for job in jobs[:20]
        ]

    def _run_job(self, job: ScanJob, payload: dict[str, object]) -> None:
        with job.lock:
            job.status = "running"
        try:
            request = scan_request_from_payload(payload)
            plan = resolve_scan_request(request, require_local_overlap=True)
            results = scan_hosts(plan.targets, plan.config, job.progress)
            with job.lock:
                job.results = results
                job.status = "complete"
                job.completed_at = time.time()
        except Exception as exc:  # The API should return errors instead of killing the worker.
            with job.lock:
                job.status = "failed"
                job.error = str(exc)
                job.completed_at = time.time()

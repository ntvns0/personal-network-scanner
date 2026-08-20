from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ProgressState:
    phase: str = "queued"
    total: int = 0
    done: int = 0
    details: dict[str, int | str] = field(default_factory=dict)
    started_at: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def start_phase(self, phase: str, total: int, **details: int | str) -> None:
        with self.lock:
            self.phase = phase
            self.total = max(total, 0)
            self.done = 0
            self.details = dict(details)
            self.started_at = time.monotonic()

    def advance(self, amount: int = 1, **details: int | str) -> None:
        with self.lock:
            self.done = min(self.done + amount, self.total) if self.total else self.done
            self.details.update(details)

    def finish_phase(self, **details: int | str) -> None:
        with self.lock:
            if self.total:
                self.done = self.total
            self.details.update(details)

    def to_dict(self) -> dict[str, Any]:
        with self.lock:
            elapsed = max(time.monotonic() - self.started_at, 0.001)
            return {
                "phase": self.phase,
                "total": self.total,
                "done": self.done,
                "details": dict(self.details),
                "elapsed": elapsed,
                "rate": self.done / elapsed,
            }

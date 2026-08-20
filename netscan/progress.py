from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import TextIO


@dataclass(slots=True)
class ProgressReporter:
    stream: TextIO = sys.stderr
    enabled: bool = True
    interval: float = 0.2
    width: int = 28
    _phase: str = ""
    _total: int = 0
    _done: int = 0
    _started_at: float = field(default_factory=time.monotonic)
    _last_rendered_at: float = 0.0
    _last_length: int = 0
    _details: dict[str, int | str] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def start_phase(self, phase: str, total: int, **details: int | str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._phase = phase
            self._total = max(total, 0)
            self._done = 0
            self._details = dict(details)
            self._started_at = time.monotonic()
            self._last_rendered_at = 0.0
            self._render(force=True)

    def advance(self, amount: int = 1, **details: int | str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._done = min(self._done + amount, self._total) if self._total else self._done
            self._details.update(details)
            self._render(force=False)

    def finish_phase(self, **details: int | str) -> None:
        if not self.enabled:
            return
        with self._lock:
            if self._total:
                self._done = self._total
            self._details.update(details)
            self._render(force=True)
            self._newline()

    def message(self, text: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._newline()
            print(text, file=self.stream)

    def close(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._newline()

    def _render(self, *, force: bool) -> None:
        now = time.monotonic()
        elapsed_since_render = now - self._last_rendered_at
        if not force and elapsed_since_render < self.interval:
            return
        line = self._format_line(now)
        if self.stream.isatty():
            padded = line.ljust(self._last_length)
            print(f"\r{padded}", end="", file=self.stream, flush=True)
            self._last_length = len(padded)
            self._last_rendered_at = now
        elif force or elapsed_since_render >= max(self.interval, 2.0):
            print(line, file=self.stream, flush=True)
            self._last_rendered_at = now

    def _format_line(self, now: float) -> str:
        elapsed = max(now - self._started_at, 0.001)
        rate = self._done / elapsed
        if self._total:
            percent = self._done / self._total
            filled = min(self.width, int(round(percent * self.width)))
            bar = "#" * filled + "-" * (self.width - filled)
            core = f"{self._phase} [{bar}] {self._done}/{self._total} {percent * 100:5.1f}%"
        else:
            core = f"{self._phase} {self._done}"
        detail_text = " ".join(f"{key}={value}" for key, value in self._details.items())
        if detail_text:
            detail_text = f" {detail_text}"
        return f"{core}{detail_text} elapsed={elapsed:0.1f}s rate={rate:0.1f}/s"

    def _newline(self) -> None:
        if self.stream.isatty() and self._last_length:
            print(file=self.stream, flush=True)
            self._last_length = 0

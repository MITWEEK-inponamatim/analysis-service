"""Minimal in-process metrics for the analysis service (Fase 4 monitoring).

Deliberately dependency-free: counters and duration summaries are enough to answer
"what ran, how long, and how often did an external dependency fail" without adding a
Prometheus stack. Values are exposed through the internal, service-key protected endpoint.
"""

import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from typing import Iterator


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = defaultdict(int)
        self._durations: dict[str, dict[str, int]] = defaultdict(lambda: {"count": 0, "sum_ms": 0, "max_ms": 0})

    @staticmethod
    def _key(name: str, labels: dict[str, object]) -> str:
        if not labels:
            return name
        rendered = ",".join(f'{key}="{value}"' for key, value in sorted(labels.items()) if value not in (None, ""))
        return f"{name}{{{rendered}}}" if rendered else name

    def inc(self, name: str, amount: int = 1, **labels: object) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] += amount

    def observe(self, name: str, seconds: float, **labels: object) -> None:
        key = self._key(name, labels)
        millis = max(0, int(seconds * 1000))
        with self._lock:
            bucket = self._durations[key]
            bucket["count"] += 1
            bucket["sum_ms"] += millis
            bucket["max_ms"] = max(bucket["max_ms"], millis)

    @contextmanager
    def timer(self, name: str, **labels: object) -> Iterator[None]:
        started = time.monotonic()
        try:
            yield
        finally:
            self.observe(name, time.monotonic() - started, **labels)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            counters = dict(self._counters)
            durations = {}
            for key, bucket in self._durations.items():
                count = bucket["count"] or 1
                durations[key] = {
                    "count": bucket["count"],
                    "avg_ms": round(bucket["sum_ms"] / count),
                    "max_ms": bucket["max_ms"],
                }
        return {"counters": dict(sorted(counters.items())), "durations": dict(sorted(durations.items()))}

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._durations.clear()


metrics = Metrics()

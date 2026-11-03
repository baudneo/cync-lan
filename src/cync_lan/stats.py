"""Process-wide event counters (dropped bytes, failed packets, reconnects, ...).

Deliberately a plain module singleton, not a field on ``g``: it has no dependencies, so any module can
``from cync_lan.stats import stats`` and tests can reset it. Published to MQTT by the MQTT client.
"""

import time
from typing import Dict


class Counters:
    def __init__(self) -> None:
        self._counts: Dict[str, int] = {}
        self._started = time.monotonic()

    def inc(self, name: str, n: int = 1) -> None:
        if n:
            self._counts[name] = self._counts.get(name, 0) + n

    def get(self, name: str) -> int:
        return self._counts.get(name, 0)

    def snapshot(self) -> Dict[str, int]:
        """Sorted copy of every counter that has been touched, plus ``uptime_seconds``."""
        out = dict(sorted(self._counts.items()))
        out["uptime_seconds"] = int(time.monotonic() - self._started)
        return out

    def reset(self) -> None:
        self._counts.clear()
        self._started = time.monotonic()


stats = Counters()

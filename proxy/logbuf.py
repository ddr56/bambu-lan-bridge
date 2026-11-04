"""Keep the last log lines in memory so the admin page can show them."""

from __future__ import annotations

import collections
import logging


class RingHandler(logging.Handler):
    def __init__(self, size: int = 2000) -> None:
        super().__init__()
        self.lines: collections.deque[tuple[int, str, str]] = collections.deque(maxlen=size)
        self.counter = 0

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.counter += 1
            self.lines.append((self.counter, record.levelname, self.format(record)))
        except Exception:  # noqa: BLE001
            self.handleError(record)

    def since(self, after: int) -> list[dict]:
        return [{"n": n, "level": lvl, "line": line} for n, lvl, line in self.lines if n > after]

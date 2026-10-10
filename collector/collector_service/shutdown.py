"""Process fail-stop guard independent of network and application cleanup."""

from __future__ import annotations

import os
import threading
import time


HARD_STOP_SECONDS = 10.0
COOPERATIVE_STOP_SECONDS = 8.0
FORCED_EXIT_STATUS = 70


class ShutdownWatchdog:
    """Prestarted daemon; first arm fixes deadlines permanently."""

    def __init__(self) -> None:
        self.deadline: float | None = None
        self.cleanup_deadline: float | None = None
        self._armed = threading.Event()
        # Capture callables before interpreter finalization can clear globals.
        armed = self._armed
        clock, sleep, terminate = time.monotonic, time.sleep, os._exit
        status = FORCED_EXIT_STATUS

        def watch() -> None:
            armed.wait()
            deadline = self.deadline
            while (remaining := deadline - clock()) > 0:
                sleep(remaining)
            # No logging, shared application lock, flush, or cleanup here.
            terminate(status)

        self._thread = threading.Thread(
            target=watch, name="collector-hard-stop", daemon=True,
        )
        self._thread.start()

    def arm(self) -> None:
        # Called only from the main thread, including its Python signal handler.
        if self.deadline is None:
            now = time.monotonic()
            self.deadline = now + HARD_STOP_SECONDS
            self.cleanup_deadline = now + COOPERATIVE_STOP_SECONDS
            self._armed.set()

    def remaining(self) -> float:
        if self.cleanup_deadline is None:
            raise RuntimeError("shutdown not armed")
        return max(0.0, self.cleanup_deadline - time.monotonic())

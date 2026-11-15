import logging
import math
import resource
import subprocess
import threading
import time
from pathlib import Path
from typing import List, Optional

import psutil

from runner.framework.models import ExecutionMetrics

logger = logging.getLogger("framework.executor")


class Executor:
    """Executes target binaries with resource monitoring and timeouts."""

    RSS_SAMPLE_INTERVAL_SECONDS = 0.001

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        command: List[str],
        env: Optional[dict] = None,
        cwd: Optional[Path] = None,
        stdin_data: Optional[str] = None,
    ) -> tuple[int, str, str, ExecutionMetrics]:
        """
        Runs the command and returns its exit code, output, and metrics. The child
        receives EOF by default or the supplied stdin_data string.
        Uses errors='replace' to safely handle corrupted/non-UTF8 memory dumps.
        """
        metrics = ExecutionMetrics()
        start_wall = time.perf_counter()
        rusage_start = resource.getrusage(resource.RUSAGE_CHILDREN)
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            env=env,
            cwd=str(cwd) if cwd else None,
        )
        stop_monitor = threading.Event()
        peak_rss_bytes = [0]
        try:
            tracked_process = psutil.Process(proc.pid)
            peak_rss_bytes[0] = tracked_process.memory_info().rss
        except psutil.NoSuchProcess:
            tracked_process = None
        except psutil.AccessDenied as exc:
            logger.warning("Cannot sample RSS for process %d: %s", proc.pid, exc)
            tracked_process = None
        monitor = None
        if tracked_process is not None:
            monitor = threading.Thread(
                target=self._sample_peak_rss,
                args=(tracked_process, stop_monitor, peak_rss_bytes),
                daemon=True,
            )
            monitor.start()

        timed_out = False
        try:
            stdout, stderr = proc.communicate(
                input=stdin_data if stdin_data is not None else "",
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()
            logger.warning("Execution timed out after %s seconds: %s", self.timeout_seconds, " ".join(command))
        finally:
            stop_monitor.set()
            if monitor is not None:
                monitor.join()

        end_wall = time.perf_counter()
        rusage_end = resource.getrusage(resource.RUSAGE_CHILDREN)

        metrics.wall_clock_time_s = self.timeout_seconds if timed_out else end_wall - start_wall
        metrics.user_time_s = max(0.0, rusage_end.ru_utime - rusage_start.ru_utime)
        metrics.sys_time_s = max(0.0, rusage_end.ru_stime - rusage_start.ru_stime)
        metrics.peak_rss_kb = (
            math.ceil(peak_rss_bytes[0] / 1024) if peak_rss_bytes[0] else None
        )
        return_code = -1 if timed_out else proc.wait()
        metrics.exit_code = return_code
        metrics.timed_out = timed_out

        return return_code, stdout, stderr, metrics

    def _sample_peak_rss(
        self,
        process: psutil.Process,
        stop_event: threading.Event,
        peak_rss_bytes: list[int],
    ) -> None:
        while not stop_event.is_set():
            try:
                peak_rss_bytes[0] = max(
                    peak_rss_bytes[0],
                    process.memory_info().rss,
                )
            except psutil.NoSuchProcess:
                return
            except psutil.AccessDenied as exc:
                logger.warning("Cannot sample RSS for process %d: %s", process.pid, exc)
                return
            if stop_event.wait(self.RSS_SAMPLE_INTERVAL_SECONDS):
                return

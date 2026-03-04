"""
TX Spike Detector — Stage 7: Actions on Objectives (Data Exfiltration).

Periodically reads /sys/class/net/<iface>/statistics/tx_bytes for all
active non-loopback interfaces and computes the upload rate. If the
upload volume exceeds a configurable threshold within the measurement
window, a 'high' severity alert is raised.

Default threshold: 50 MB uploaded within a single 60-second window.
This is deliberately conservative to avoid false-positives from large
but legitimate transfers (e.g., backups, software updates).

The threshold can be overridden via the AppSetting key:
  tx_spike_threshold_mb  (integer, megabytes per window)
"""

import logging
import os
import threading
import time

from django.db import close_old_connections

from core.alert_engine import create_alert_with_geo

log = logging.getLogger("core.tx_spike_detector")

_POLL_INTERVAL = 60          # seconds between samples
_DEFAULT_THRESHOLD_MB = 50   # MB uploaded in one interval to trigger alert
_COOLDOWN = 300              # seconds before re-alerting for the same interface
_SYS_NET = "/sys/class/net"


def _get_threshold_mb() -> float:
    """Read configurable threshold from settings_api, with fallback."""
    try:
        from core import settings_api
        val = settings_api.get_int("tx_spike_threshold_mb")
        if val and val > 0:
            return float(val)
    except Exception:
        pass
    return float(_DEFAULT_THRESHOLD_MB)


def _read_tx_bytes(iface: str) -> int | None:
    """Read current TX byte counter for an interface."""
    path = os.path.join(_SYS_NET, iface, "statistics", "tx_bytes")
    try:
        with open(path, "r") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _active_interfaces() -> list[str]:
    """Return non-loopback interfaces that have a tx_bytes counter."""
    ifaces = []
    try:
        for iface in os.listdir(_SYS_NET):
            if iface == "lo":
                continue
            if os.path.exists(os.path.join(_SYS_NET, iface, "statistics", "tx_bytes")):
                ifaces.append(iface)
    except OSError as e:
        log.debug("Cannot list %s: %s", _SYS_NET, e)
    return ifaces


class TxSpikeDetector(threading.Thread):
    """
    Background thread that monitors per-interface TX byte counters and
    raises an alert when an upload spike consistent with data exfiltration
    is detected.
    """

    def __init__(self, interval: int = _POLL_INTERVAL):
        super().__init__(daemon=True, name="TxSpikeDetector")
        self.interval = interval
        self.running = True
        # iface -> last tx_bytes value
        self._prev: dict[str, int] = {}
        # iface -> last alert timestamp
        self._last_alert: dict[str, float] = {}

    def run(self):
        log.info("TxSpikeDetector started (interval=%ds)", self.interval)
        # Warm up: record initial byte counts without alerting
        for iface in _active_interfaces():
            val = _read_tx_bytes(iface)
            if val is not None:
                self._prev[iface] = val

        time.sleep(self.interval)


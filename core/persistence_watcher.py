"""
Persistence Watcher — Stage 5: Installation.

Monitors common persistence paths for unexpected additions, deletions,
or modifications. Attackers typically install persistence via:
  - crontab entries (/etc/cron.d, /var/spool/cron/crontabs, /etc/crontab)
  - systemd user units (~/.config/systemd/user/)

On first run a baseline hash dict is built silently. On subsequent polls,
any deviation raises a 'high' severity alert.
"""

import hashlib
import logging
import os
import threading
import time
from pathlib import Path

from django.db import close_old_connections

from core.alert_engine import create_alert_with_geo

log = logging.getLogger("core.persistence_watcher")

_POLL_INTERVAL = 30  # seconds


def _default_watch_paths() -> list[Path]:
    """Return persistence paths to monitor on this machine."""
    paths = [
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path("/var/spool/cron/crontabs"),
    ]
    # User systemd units (expand ~)
    user_systemd = Path.home() / ".config" / "systemd" / "user"
    if user_systemd.exists():
        paths.append(user_systemd)
    return paths


def _hash_file(path: Path) -> str:
    """Return SHA-256 hex digest of a file, or empty string on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _snapshot(paths: list[Path]) -> dict[str, str]:
    """
    Walk each path (file or directory) and return a mapping of
    absolute-path-string → sha256 for every file found.
    """
    state: dict[str, str] = {}
    for root in paths:
        if root.is_file():
            digest = _hash_file(root)
            if digest:
                state[str(root)] = digest
        elif root.is_dir():
            try:
                for entry in os.scandir(root):
                    if entry.is_file(follow_symlinks=False):
                        digest = _hash_file(Path(entry.path))
                        if digest:
                            state[entry.path] = digest
            except PermissionError:
                log.debug("No read permission for %s", root)
    return state


def _emit_alert(event: str, path: str):
    """Raise a persistence alert via the alert engine."""
    msg = f"Persistence change detected [{event}]: {path}"
    log.warning(msg)
    create_alert_with_geo(
        src_ip=None,
        message=msg,
        severity="high",
        alert_type="Persistence Change",
        category="installation:persistence",
    )


class PersistenceWatcher(threading.Thread):
    """
    Background thread that baselines and monitors cron/systemd persistence
    paths for attacker-installed backdoors.
    """

    def __init__(self, interval: int = _POLL_INTERVAL):
        super().__init__(daemon=True, name="PersistenceWatcher")
        self.interval = interval
        self.running = True
        self._baseline: dict[str, str] | None = None
        self._watch_paths = _default_watch_paths()

    def run(self):
        log.info(
            "PersistenceWatcher started — monitoring %d paths",
            len(self._watch_paths),
        )
        while self.running:
            try:
                self._poll()
            except Exception:
                log.exception("PersistenceWatcher: unexpected error in poll")
            finally:
                close_old_connections()
            time.sleep(self.interval)

    def _poll(self):
        current = _snapshot(self._watch_paths)

import json
import logging
import socket
from pathlib import Path
from typing import List

log = logging.getLogger(__name__)

_CONFIG_PATH = Path.home() / ".flow" / "settings.json"
_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)


def _load() -> dict:
    if not _CONFIG_PATH.exists():
        return {}
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _save(data: dict) -> None:
    try:
        with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        log.warning("Failed to save settings to %s: %s", _CONFIG_PATH, e)


def get_ignored_ips() -> List[str]:
    cfg = _load()
    return cfg.get("ignored_ips", [])


def set_ignored_ips(ips: List[str]) -> None:
    cfg = _load()
    cfg["ignored_ips"] = ips
    _save(cfg)


def add_ignored_ip(ip: str) -> None:
    ips = set(get_ignored_ips())
    ips.add(ip)
    set_ignored_ips(sorted(ips))


def remove_ignored_ip(ip: str) -> None:
    ips = set(get_ignored_ips())
    ips.discard(ip)
    set_ignored_ips(sorted(ips))


def clear_ignored_ips() -> None:
    cfg = _load()
    cfg["ignored_ips"] = []
    _save(cfg)


def detect_primary_ip(timeout: float = 0.5) -> str | None:
    """Return the primary outbound IP used for Internet access. Non-blocking and does not send packets to network."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.connect(("8.8.8.8", 80))
        addr = s.getsockname()[0]
        s.close()
        return addr
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return None

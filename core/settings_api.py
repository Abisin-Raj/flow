"""
Settings API Module.

This module provides a unified interface for accessing and key-value application settings.
It sits on top of the `AppSetting` model and implements:
1.  In-memory caching with TTL to reduce DB hits.
2.  Type conversion helpers (bool, int, list).
3.  Logic for IP ignore lists and private IP detection.
"""

from __future__ import annotations

import logging
import threading
import time
import socket
from typing import Dict, Optional, List

from django.db import OperationalError

from core.models import AppSetting

log = logging.getLogger(__name__)

# Constants moved from app_settings.py
DEMO_MODE = False

# Thresholds
HIGH_RATE_LIMIT = 100
HIGH_RATE_WINDOW_SECONDS = 10
PORTSCAN_DISTINCT_PORTS = 20
PORTSCAN_WINDOW_SECONDS = 10
SYN_THRESHOLD = 20

# Common suspicious ports (reverse shells, trojans, etc)
SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 1337, 31337, 12345, 
    # Add more as needed
}

DEFAULTS: Dict[str, str] = {
    # detector tuning
    "detector.window_seconds": "10",
    "detector.fast_ports": "50",
    "detector.brute_ports": "200",
    "detector.brute_window": "5",
    "detector.slow_ports": "15",
    "detector.cooldown_seconds": "30",
    "detector.cooldown_seconds": "30",
    "detector.max_store": "1000",
    "detector.high_rate_limit": "100",
    # retention
    "retention.days": "7",
    # UI
    "ui.dashboard_refresh_ms": "10000",
    # ignore / whitelist
    "detector.ignore_my_ip": "1",  # "1" or "0"
    "detector.my_ip": "",  # auto detected and saved by UI
    "detector.ignore_private_ranges": "0",  # "1" or "0"
    "detector.whitelist_ips": "",  # comma separated IPs
    "enable_raw_sniffer": "0",
    "reverse_shell_ports": "4444,5555,1337",
    "allow_firewall_actions": "0",
}

_cache: Dict[str, str] = {}
_cache_at: float = 0.0
_cache_lock = threading.Lock()
_CACHE_TTL_SECONDS = 5.0


def _load_cache(force: bool = False) -> None:
    """
    Refresh the in-memory settings cache from the database.
    
    Args:
        force (bool): If True, ignore TTL and force reload.
    """
    global _cache_at, _cache
    now = time.time()
    with _cache_lock:
        if not force and (now - _cache_at) < _CACHE_TTL_SECONDS and _cache:
            return
        data: Dict[str, str] = {}
        try:
            for row in AppSetting.objects.all():
                data[row.key] = row.value
        except OperationalError:
            data = {}
        except Exception:
            data = {}
        # apply defaults for missing keys
        for k, v in DEFAULTS.items():
            if k not in data:
                data[k] = v
        _cache = data
        _cache_at = now


def get(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Retrieve a raw string setting value.
    """
    _load_cache()
    if key in _cache:
        return _cache[key]
    if key in DEFAULTS:
        return DEFAULTS[key]
    return default


def set_value(key: str, value: str) -> None:
    """
    Write a setting to the DB and update the cache.
    """
    value = "" if value is None else str(value)
    
    try:
        AppSetting.objects.update_or_create(
            key=key,
            defaults={"value": value},
        )
    except Exception as e:
        log.warning("Failed to save setting %s to database: %s", key, e)

    with _cache_lock:
        _cache[key] = value
        _cache_at = time.time()


def set_bulk(items: Dict[str, str]) -> None:
    """
    Update multiple settings in a single transaction to avoid lock contention.
    """
    from django.db import transaction
    
    # Prepare cache updates
    with _cache_lock:
        for k, v in items.items():
            _cache[k] = str(v)
        _cache_at = time.time()

    try:
        with transaction.atomic():
            for key, value in items.items():
                value = "" if value is None else str(value)
                AppSetting.objects.update_or_create(
                    key=key,
                    defaults={"value": value},
                )
    except Exception as e:
        log.warning("Failed to bulk save settings: %s", e)


def get_detector_settings() -> Dict[str, int]:
    """
    Get a dictionary of all detector tuning parameters, cast to integers.
    Uses defaults if specific keys are missing.
    """
    _load_cache()

    def _int(key: str, fallback: int) -> int:
        try:
            return int(_cache.get(key, DEFAULTS.get(key, str(fallback))))
        except Exception:
            return int(fallback)

    return {
        "window_seconds": _int("detector.window_seconds", 10),
        "fast_ports": _int("detector.fast_ports", 50),
        "brute_ports": _int("detector.brute_ports", 200),
        "brute_window": _int("detector.brute_window", 5),
        "slow_ports": _int("detector.slow_ports", 15),
        "cooldown_seconds": _int("detector.cooldown_seconds", 30),
        "max_store": _int("detector.max_store", 1000),
        "high_rate_limit": _int("detector.high_rate_limit", 100),
    }


def get_bool(key: str, default: bool = False) -> bool:
    val = get(key, None)
    if val is None:
        return default
    v = val.strip().lower()
    return v in ("1", "true", "yes", "on")


def firewall_allowed() -> bool:
    return get_bool("allow_firewall_actions")


def is_firewall_dry_run() -> bool:
    """
    Check if firewall is in dry-run mode.
    In dry-run mode, Flow logs block decisions but doesn't actually touch nftables.
    Useful for testing, demos, and safe validation.
    
    Enable by setting AppSetting: key='firewall_dry_run', value='true'
    """
    return get_bool("firewall_dry_run")


def get_list(key: str) -> list[str]:
    val = get(key, "") or ""
    items = [p.strip() for p in val.split(",") if p.strip()]
    return items



def get_port_list(key: str, default: str = "") -> list[int]:
    """
    Return a list of ints for a comma separated port list setting.
    Example: "4444,5555,1337" -> [4444, 5555, 1337]
    """
    raw = get(key, default)
    if not raw:
        return []
    parts = [p.strip() for p in str(raw).split(",") if p.strip()]
    ports = []
    for p in parts:
        try:
            ports.append(int(p))
        except ValueError:
            continue
    return ports


IGNORED_IPS_KEY = "detector.whitelist_ips"


def get_ignored_ips() -> List[str]:
    raw = get(IGNORED_IPS_KEY, "") or ""
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    # Deduplicate while preserving order
    seen = set()
    result: List[str] = []
    for ip in parts:
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def set_ignored_ips(ips: List[str]) -> None:
    value = ",".join(sorted(set(ip.strip() for ip in ips if ip.strip())))
    set_value(IGNORED_IPS_KEY, value)


def add_ignored_ip(ip: str) -> None:
    ip = ip.strip()
    if not ip:
        return
    ips = get_ignored_ips()
    if ip not in ips:
        ips.append(ip)
        set_ignored_ips(ips)


def remove_ignored_ip(ip: str) -> None:
    ip = ip.strip()
    if not ip:
        return
    ips = [p for p in get_ignored_ips() if p != ip]
    set_ignored_ips(ips)


def detect_local_ip() -> str:
    """
    Best-effort guess of primary local IP.
    This is used only for "Ignore my IP" UI.
    
    It tries to connect to a public IP (8.8.8.8) to see which interface
    is picked by the OS routing table.
    """
    # try connected UDP trick
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip:
                return ip
        finally:
            s.close()
    except Exception as e:
        log.debug("Failed to detect local IP via socket: %s", e)

    # fallback
    try:
        name = socket.gethostname()
        ip = socket.gethostbyname(name)
        return ip
    except Exception:
        return ""


def get_my_ip() -> str:
    val = get("detector.my_ip", "") or ""
    if val:
        return val
    ip = detect_local_ip()
    if ip:
        set_value("detector.my_ip", ip)
    return ip


def is_private_ip(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            parts = ip.split(".")
            if len(parts) >= 2:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
        except Exception:
            return False
    if ip.startswith("127.") or ip == "localhost" or ip == "::1":
        return True
    return False


def is_ip_ignored(ip: Optional[str]) -> bool:
    """
    Check if an IP should be ignored (allowed) based on current settings.
    
    Checks:
    1. Static allowlist.
    2. "Ignore My IP" dynamic check.
    3. "Ignore Private Ranges" check.
    
    Used by detectors and alert engine to skip alerts on trusted IPs.
    """
    if not ip:
        return False

    ip = str(ip).strip()
    if not ip:
        return False

    # static whitelist list
    wl = set(get_list("detector.whitelist_ips"))
    if ip in wl:
        return True

    # ignore my IP toggle
    if get_bool("detector.ignore_my_ip", False):
        my_ip = get_my_ip()
        if my_ip and ip == my_ip:
            return True

    # ignore private ranges toggle
    if get_bool("detector.ignore_private_ranges", False):
        if is_private_ip(ip):
            return True

    return False


def get_service_flags() -> Dict[str, bool]:
    """
    Return status of background services (default True).
    """
    return {
        "collectors": get_bool("service.collectors", True),
        "folder_watcher": get_bool("service.folder_watcher", True),
        "sniffer": get_bool("service.sniffer", True),
        "light_sniffer": get_bool("service.light_sniffer", True),
        "alert_watcher": get_bool("service.alert_watcher", True),
    }


def set_service_flag(service: str, enabled: bool) -> None:
    """
    Enable or disable a background service.
    """
    key = f"service.{service}"
    val = "1" if enabled else "0"
    set_value(key, val)


def get_ignored_processes() -> list[str]:
    """
    Return list of process names that should not trigger alerts.
    """
    try:
        val = get("ignored_processes", "")
        if not val:
            return []
        import json
        return json.loads(val)
    except Exception:
        log.warning("settings_api.get_ignored_processes failed, returning []")
        return []


def set_ignored_processes(lst):
    """
    Set ignored processes list. Accepts list or comma-separated string.
    """
    try:
        import json
        if isinstance(lst, str):
            lst = [x.strip() for x in lst.split(",") if x.strip()]
        set_value("ignored_processes", json.dumps(lst))
    except Exception as e:
        log.exception("set_ignored_processes failed: %s", e)


def is_process_ignored_name(name: str) -> bool:
    """
    Check if a process name is in the ignored list.
    """
    name = (name or "").strip().lower()
    if not name:
        return False
    for p in get_ignored_processes():
        if p.strip().lower() == name:
            return True
    return False

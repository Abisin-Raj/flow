import time
import threading
import logging
import ipaddress

from core.alert_engine import create_alert_with_geo

log = logging.getLogger("core.rare_port_detector")

# Config defaults
_WINDOW_SECONDS = 60  # time window to observe repeated use
_THRESHOLD = 8  # how many connections before we alert
_COOLDOWN_SECONDS = 300  # do not alert again for same src+port within 5 minutes

# Ports you expect to see often
_COMMON_PORTS = {
    80,  # HTTP
    443,  # HTTPS
    53,  # DNS
    123,  # NTP
    587,  # SMTP submission
    25,  # SMTP
    110,  # POP3
    143,  # IMAP
    993,  # IMAPS
    995,  # POP3S
    22,  # SSH
    3389,  # RDP
    51820,  # WireGuard default, avoid spamming your own VPN
}

# state: (src_ip, dst_port) -> [timestamps...]
_events = {}
_events_lock = threading.Lock()

# cooldown: (src_ip, dst_port) -> last_alert_ts
_last_alert = {}
_last_alert_lock = threading.Lock()


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _is_local_to_internet(src_ip: str, dst_ip: str) -> bool:
    if not src_ip or not dst_ip:
        return False
    if not _is_private_ip(src_ip):
        return False
    if _is_private_ip(dst_ip):
        return False
    return True


def _record_event(src_ip: str, dst_port: int, now_ts: float):
    key = (src_ip, dst_port)
    with _events_lock:
        lst = _events.get(key)
        if lst is None:
            lst = []
            _events[key] = lst
        lst.append(now_ts)

        cutoff = now_ts - _WINDOW_SECONDS
        while lst and lst[0] < cutoff:
            lst.pop(0)

        if not lst:
            _events.pop(key, None)


def _should_alert_now(src_ip: str, dst_port: int, now_ts: float) -> bool:
    key = (src_ip, dst_port)

    with _events_lock:
        lst = _events.get(key, [])
        count = len(lst)

    if count < _THRESHOLD:
        return False

    with _last_alert_lock:
        last = _last_alert.get(key, 0.0)
        if now_ts - last < _COOLDOWN_SECONDS:
            return False
        _last_alert[key] = now_ts

    return True


def handle_connection(
    src_ip: str, dst_ip: str, dst_port: int, protocol: str, now_ts: float = None
):
    """
    Called from collectors for each outbound connection.
    Decides if it is a rare outbound port and raises an alert when needed.
    """
    try:
        if now_ts is None:
            now_ts = time.time()

        if not src_ip or not dst_ip:
            return

        try:
            port = int(dst_port)
        except Exception:
            return

        if port <= 0 or port > 65535:
            return

        if port in _COMMON_PORTS:
            return

        if protocol and str(protocol).upper() not in ("TCP", "UDP"):
            return

        if not _is_local_to_internet(src_ip, dst_ip):
            return

        _record_event(src_ip, port, now_ts)

        if not _should_alert_now(src_ip, port, now_ts):
            return

        note = (
            f"Suspicious outbound activity: local host {src_ip} is repeatedly "
            f"connecting to external host {dst_ip} on uncommon port {port} "
            f"within a short time window."
        )

        # high if high numbered port, else medium
        severity = "high" if port >= 1024 else "medium"

        try:
            create_alert_with_geo(
                src_ip=src_ip,
                alert_type="Suspicious Outbound Port",
                message=note,
                severity=severity,
                category="tunnel:rare_port",
            )
            log.info(
                "Rare-port alert created for %s -> %s:%d severity=%s",
                src_ip,
                dst_ip,
                port,
                severity,
            )
        except Exception:
            log.exception(
                "Failed creating rare-port alert for %s -> %s:%d", src_ip, dst_ip, port
            )

    except Exception:
        log.exception("handle_connection rare-port detector error")


def cleanup(max_age: float = 3600):
    """
    Optional periodic cleanup to keep memory bounded.
    Can be called from a timer or left unused.
    """
    now_ts = time.time()

    with _events_lock:
        for key in list(_events.keys()):
            lst = _events[key]
            cutoff = now_ts - _WINDOW_SECONDS
            while lst and lst[0] < cutoff:
                lst.pop(0)
            if not lst:
                _events.pop(key, None)

    with _last_alert_lock:
        for key, ts in list(_last_alert.items()):
            if now_ts - ts > max_age:
                _last_alert.pop(key, None)

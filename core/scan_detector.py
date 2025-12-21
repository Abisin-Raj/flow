"""
Scan Detector Module.

This module analyzes network packet events to detect port scanning behavior.
It supports detecting:
1.  SYN Flood (high frequency of events).
2.  Brute force port scanning (many ports).
3.  Fast scanning (moderate speed).
4.  Horizontal sweeping (same port, many hosts).
5.  Slow/Stealth scanning.
"""

from collections import deque, defaultdict
import threading
import time
from typing import List, Tuple, Optional

# Configuration for detection thresholds
_WINDOW_SECONDS = 10     # Recent activity window
_FAST_PORTS = 50         # Threshold for fast scan
_BRUTE_PORTS = 200       # Threshold for brute force
_BRUTE_WINDOW = 5        # Short window for brute force
_SLOW_PORTS = 15         # Threshold for slow scan
_COOLDOWN_SECONDS = 30   # Minimum time between alerts for same source
_MAX_STORE = 1000        # Max events to store per source IP

# Port sweep and flood configuration
_SWEEP_HOSTS = 20        # Unique hosts for sweep detection
_FLOOD_EVENTS = 300      # Events count for SYN flood
_FLOOD_WINDOW = 5        # Window for SYN flood detection

_events = defaultdict(lambda: deque())
_events_lock = threading.Lock()

_last_alert_ts = {}
_last_alert_lock = threading.Lock()


def _trim_events_for_src(src_ip: str, now_ts: float, window: float):
    dq = _events[src_ip]
    cutoff = now_ts - window
    # drop too old
    while dq and dq[0][0] < cutoff:
        dq.popleft()
    # hard cap size
    while len(dq) > _MAX_STORE:
        dq.popleft()


def note_packet(
    src_ip: str, dst_port: int, ts: Optional[float] = None, dst_ip: Optional[str] = None
):
    """
    Record a network event (e.g., SYN packet) for analysis.

    Args:
        src_ip (str): Source IP address.
        dst_port (int): Destination port.
        ts (float, optional): Timestamp. Defaults to now.
        dst_ip (str, optional): Destination IP (for sweep detection).
    """
    if not src_ip:
        return
    if ts is None:
        ts = time.time()

    try:
        p = int(dst_port)
    except Exception:
        return

    with _events_lock:
        dq = _events[src_ip]
        dq.append((ts, p, dst_ip or ""))
        _trim_events_for_src(src_ip, ts, _WINDOW_SECONDS)


def _unique_ports_in_window(src_ip: str, now_ts: float, window_seconds: float) -> int:
    """Kept for compatibility, counts unique ports in window."""
    with _events_lock:
        if src_ip not in _events:
            return 0
        cutoff = now_ts - window_seconds
        ports = {p for ts, p, _ in _events[src_ip] if ts >= cutoff}
        return len(ports)


def classify_scan(
    events: List[Tuple[float, int, str]], now_ts: Optional[float] = None
) -> str:
    """
    Analyze a list of events to classify the scan type.

    Args:
        events (list): List of (timestamp, port, dst_ip).
        now_ts (float, optional): Current timestamp.

    Returns:
        str: 'syn_flood', 'brute', 'fast', 'sweep', 'slow', or 'unknown'.
    """
    if now_ts is None:
        now_ts = time.time()

    if not events:
        return "unknown"

    recent_window = now_ts - _WINDOW_SECONDS
    brute_window = now_ts - _BRUTE_WINDOW
    flood_window = now_ts - _FLOOD_WINDOW

    ports_recent = {p for ts, p, _ in events if ts >= recent_window}
    ports_brute = {p for ts, p, _ in events if ts >= brute_window}
    hosts_recent = {dst for ts, _, dst in events if ts >= recent_window and dst}

    # SYN flood heuristic
    flood_count = sum(1 for ts, _, _ in events if ts >= flood_window)
    if flood_count >= _FLOOD_EVENTS:
        return "syn_flood"

    if len(ports_brute) >= _BRUTE_PORTS:
        return "brute"

    if len(ports_recent) >= _FAST_PORTS:
        return "fast"

    # port sweep, many hosts on same port
    if hosts_recent:
        port_hosts = {}
        for ts, p, dst in events:
            if ts < recent_window or not dst:
                continue
            s = port_hosts.setdefault(p, set())
            s.add(dst)
        for p, hostset in port_hosts.items():
            if len(hostset) >= _SWEEP_HOSTS:
                return "sweep"

    if len(ports_recent) >= _SLOW_PORTS:
        return "slow"

    return "unknown"


def evaluate_for_alert(
    src_ip: str, now_ts: Optional[float] = None, *, produce_cooldown: bool = True
) -> Optional[str]:
    """
    Evaluate if a source IP needs an alert generated.
    
    This checks the recent events for the IP, classifies the activity,
    and applies cooldown logic to prevent alert fatigue.

    Args:
        src_ip (str): Source IP.
        now_ts (float, optional): Timestamp.
        produce_cooldown (bool): If True, updates the last alert timestamp.

    Returns:
        str or None: Scan category if alert should be produced, else None.
    """
    if now_ts is None:
        now_ts = time.time()

    with _events_lock:
        dq = _events.get(src_ip)
        if not dq:
            return None
        events = list(dq)

    category = classify_scan(events, now_ts)
    if category == "unknown":
        return None

    if not produce_cooldown:
        return category

    with _last_alert_lock:
        last = _last_alert_ts.get(src_ip, 0.0)
        if now_ts - last < _COOLDOWN_SECONDS:
            return None
        _last_alert_ts[src_ip] = now_ts

    return category


def get_recent_events(
    src_ip: str, now_ts: Optional[float] = None, window_seconds: Optional[float] = None
):
    if now_ts is None:
        now_ts = time.time()
    if window_seconds is None:
        window_seconds = _WINDOW_SECONDS

    with _events_lock:
        dq = _events.get(src_ip, deque())
        cutoff = now_ts - window_seconds
        return [(ts, p, dst) for ts, p, dst in dq if ts >= cutoff]


def reset_src(src_ip: str):
    with _events_lock:
        _events.pop(src_ip, None)
    with _last_alert_lock:
        _last_alert_ts.pop(src_ip, None)


def _cleanup_aged(max_age: float = 3600):
    now = time.time()
    cutoff = now - max_age

    with _events_lock:
        for src in list(_events.keys()):
            dq = _events[src]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                _events.pop(src, None)

    with _last_alert_lock:
        for src, ts in list(_last_alert_ts.items()):
            if ts < cutoff:
                _last_alert_ts.pop(src, None)


class _Detector:
    def note_packet(
        self,
        src_ip: str,
        dst_port: int,
        ts: Optional[float] = None,
        dst_ip: Optional[str] = None,
    ):
        note_packet(src_ip, dst_port, ts, dst_ip)

    def evaluate(self, src_ip: str, now_ts: Optional[float] = None):
        return evaluate_for_alert(src_ip, now_ts)

    def recent(
        self,
        src_ip: str,
        now_ts: Optional[float] = None,
        window_seconds: Optional[float] = None,
    ):
        return get_recent_events(src_ip, now_ts, window_seconds)


detector = _Detector()

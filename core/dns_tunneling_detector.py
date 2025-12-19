import time
import statistics
import logging
from collections import deque, defaultdict
from typing import Optional

log = logging.getLogger(__name__)

# Tuning parameters
_WINDOW_SECONDS = 10
_MIN_QUERIES = 5
_AVG_LEN_THRESHOLD = 50  # Average subdomain length
_ENTROPY_THRESHOLD = 4.5 # Not using entropy yet, but simple length heuristic first

_events = defaultdict(lambda: deque())

def note_query(src_ip: str, query_name: str, qtype: int, ts: Optional[float] = None):
    """Record a DNS query for analysis."""
    if not src_ip or not query_name:
        return
    if ts is None:
        ts = time.time()
    
    # Store relevant data: timestamp, length of qname
    # We strip the root dot if present
    name = query_name.rstrip('.')
    length = len(name)
    
    events = _events[src_ip]
    events.append((ts, length, name))
    
    # Cleanup old events
    cutoff = ts - _WINDOW_SECONDS
    while events and events[0][0] < cutoff:
        events.popleft()

def evaluate(src_ip: str, now_ts: Optional[float] = None) -> Optional[str]:
    """
    Check if src_ip is exhibiting tunneling behavior.
    Returns 'dns_tunneling' if detected, else None.
    """
    if now_ts is None:
        now_ts = time.time()
        
    events = _events.get(src_ip)
    if not events:
        return None
        
    # Analyze only recent events
    cutoff = now_ts - _WINDOW_SECONDS
    recent_events = [e for e in events if e[0] >= cutoff]
    
    if len(recent_events) < _MIN_QUERIES:
        return None
        
    # Calculate average query length
    lengths = [len(name) for _, length, name in recent_events]
    avg_len = statistics.mean(lengths)
    
    # Heuristic 1: High average length is suspicious for tunneling
    if avg_len > _AVG_LEN_THRESHOLD:
        log.info(f"TUNNEL DETECTED ({src_ip}): {len(recent_events)} queries, avg len {avg_len:.1f}")
        return "dns_tunneling"
        
    return None

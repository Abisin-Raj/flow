"""
Block Policy Module with Explainability.

Centralized logic for determining how long an IP should be blocked based on:
- Alert severity
- Alert type  
- Repeat offender history

Returns both timeout and human-readable explanation for audit/UI.
"""

from datetime import timedelta
from django.utils import timezone
from typing import Tuple, Dict, Any

# Safety cap
MAX_TIMEOUT_SECONDS = 24 * 60 * 60  # 24 hours

# Base timeouts by severity (in seconds)
SEVERITY_BASE = {
    "low": 60,          # 1 minute
    "medium": 300,      # 5 minutes
    "high": 3600,       # 1 hour
    "critical": 86400,  # 24 hours
}

# Certain alert types deserve harsher handling
TYPE_MULTIPLIER = {
    "port_scan": 1,
    "port scan": 1,
    "bruteforce": 2,
    "brute_force": 2,
    "malware_traffic": 4,
    "malware": 4,
    "c2_callback": 8,
    "syn_flood": 2,
    "arp_spoofing": 4,
}

# Repeat offender settings
REPEAT_WINDOW_SECONDS = 3600   # Look back 1 hour
REPEAT_THRESHOLD = 3           # Number of alerts to trigger escalation


def _get_type_multiplier(alert_type: str) -> Tuple[int, str]:
    """Get multiplier for alert type, returns (multiplier, matched_key)."""
    alert_type_lower = (alert_type or "").lower().replace(" ", "_")
    for key, mult in TYPE_MULTIPLIER.items():
        if key in alert_type_lower:
            return mult, key
    return 1, "default"


def _is_repeat_offender(alert) -> Tuple[bool, int]:
    """Check if this IP is a repeat offender. Returns (is_repeat, count)."""
    if not alert.src_ip:
        return False, 0
    
    try:
        recent_count = (
            alert.__class__.objects.filter(
                src_ip=alert.src_ip,
                timestamp__gte=timezone.now() - timedelta(seconds=REPEAT_WINDOW_SECONDS),
            )
            .exclude(id=alert.id)
            .count()
        )
        return recent_count >= REPEAT_THRESHOLD, recent_count
    except Exception:
        return False, 0


def calculate_block_timeout(alert) -> Tuple[int, Dict[str, Any]]:
    """
    Calculate block duration in seconds based on alert characteristics.
    
    Returns:
        Tuple[int, Dict]: (timeout_seconds, explanation_dict)
        
    The explanation dict contains all factors that contributed to the decision,
    useful for audit logs, UI display, and debugging false positives.
    """
    # Get severity base
    severity = (alert.severity or "medium").lower()
    base_timeout = SEVERITY_BASE.get(severity, 300)

    # Get type multiplier
    alert_type = alert.alert_type or "unknown"
    type_multiplier, matched_type = _get_type_multiplier(alert_type)

    # Check repeat offender
    is_repeat, repeat_count = _is_repeat_offender(alert)
    repeat_multiplier = 2 if is_repeat else 1

    # Calculate timeout
    raw_timeout = base_timeout * type_multiplier * repeat_multiplier
    final_timeout = min(raw_timeout, MAX_TIMEOUT_SECONDS)
    was_capped = raw_timeout > MAX_TIMEOUT_SECONDS

    # Build explanation
    explanation = {
        "severity": severity,
        "severity_base_seconds": base_timeout,
        "alert_type": alert_type,
        "matched_type_key": matched_type,
        "type_multiplier": type_multiplier,
        "repeat_offender": is_repeat,
        "repeat_count": repeat_count,
        "repeat_multiplier": repeat_multiplier,
        "raw_timeout_seconds": raw_timeout,
        "final_timeout_seconds": final_timeout,
        "capped": was_capped,
    }

    return final_timeout, explanation


def format_explanation(explanation: Dict[str, Any]) -> str:
    """
    Format explanation dict into human-readable text for alert messages.
    """
    lines = [
        "",
        "Auto-Mitigation Details:",
        f"  Severity: {explanation['severity']} (base {explanation['severity_base_seconds']}s)",
        f"  Attack Type: {explanation['alert_type']} (×{explanation['type_multiplier']})",
        f"  Repeat Offender: {'Yes' if explanation['repeat_offender'] else 'No'} "
        f"({explanation['repeat_count']} recent alerts, ×{explanation['repeat_multiplier']})",
        f"  Final Block Duration: {explanation['final_timeout_seconds']}s",
    ]
    
    if explanation['capped']:
        lines.append(f"  Note: Duration capped at 24 hours")
    
    return "\n".join(lines)

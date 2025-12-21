"""
Unblock Policy Module.

Determines when an IP should be unblocked based on alert state.
This ensures IPs are only unblocked when safe (no unresolved alerts remain).
"""

from core.models import Alert


def should_unblock_ip(ip: str) -> bool:
    """
    Decide if an IP should be unblocked.
    
    Returns True only if no unresolved alerts remain for this IP.
    This prevents premature unblocking when multiple alerts exist.
    
    Args:
        ip: The IP address to check
        
    Returns:
        bool: True if safe to unblock, False otherwise
    """
    if not ip:
        return False

    # Check if any active (unresolved) alerts exist for this IP
    active_alerts = Alert.objects.filter(
        src_ip=ip,
        resolved=False,
    ).exists()

    # Only unblock if NO active alerts remain
    return not active_alerts

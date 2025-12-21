"""
Alert Resolution Module (PostgreSQL-safe).

Provides centralized, transaction-safe logic for resolving alerts and handling
the associated firewall unblocking when appropriate.

Uses select_for_update() to prevent race conditions when multiple alerts
reference the same IP or when UI and background threads access simultaneously.
"""

import logging
from django.db import transaction
from core.models import Alert, BlockedIp
from core import firewall
from core.unblock_policy import should_unblock_ip

logger = logging.getLogger("core.alert_resolution")


@transaction.atomic
def resolve_alert(alert_id: int) -> tuple[bool, str]:
    """
    Marks an alert as resolved and unblocks IP if safe.
    
    PostgreSQL-safe implementation with:
    - transaction.atomic() for consistency
    - select_for_update() to prevent race conditions
    - Proper row locking to avoid double-resolution
    
    This is the canonical way to resolve alerts. It ensures:
    - Alert is marked resolved in database
    - IP is unblocked only if no other unresolved alerts exist
    - BlockedIp record is cleaned up
    - All actions are logged
    - No race conditions or deadlocks
    
    Args:
        alert_id: Database ID of the alert to resolve
        
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Lock the alert row to avoid double-resolution
        alert = (
            Alert.objects
            .select_for_update()
            .get(id=alert_id)
        )
    except Alert.DoesNotExist:
        return False, "Alert not found"

    if alert.resolved:
        return True, "Already resolved"

    # Mark as resolved
    alert.resolved = True
    alert.save(update_fields=["resolved"])
    logger.info(f"Alert {alert_id} marked as resolved")

    ip = alert.src_ip
    if not ip:
        return True, "Resolved (no IP associated)"

    # Check if other active alerts exist for this IP
    if not should_unblock_ip(ip):
        logger.info(f"IP {ip} not unblocked: other active alerts exist")
        return True, "Resolved (other alerts still active)"

    # Lock the blocked IP row if it exists
    blocked = (
        BlockedIp.objects
        .select_for_update()
        .filter(ip=ip)
        .first()
    )

    if not blocked:
        return True, "Resolved (IP not in block list)"

    # Call firewall helper
    success, msg = firewall.unblock_ip(ip)

    if success:
        blocked.delete()
        logger.info(f"Unblocked IP {ip} after alert resolution")
        return True, f"Resolved and unblocked {ip}"
    else:
        logger.warning(f"Failed to unblock IP {ip}: {msg}")
        return True, f"Resolved but unblock failed: {msg}"


def resolve_alert_by_instance(alert: Alert) -> tuple[bool, str]:
    """
    Convenience wrapper that takes an Alert instance instead of ID.
    Note: This re-fetches the alert inside the transaction for safety.
    """
    return resolve_alert(alert.id)

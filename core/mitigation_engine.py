"""
Mitigation Engine.

This module defines logic for suggesting mitigation actions based on alerts.
It analyzes the properties of an alert (type, message, IPs) and recommends
actions like blocking an IP or marking an alert as resolved.
"""

import logging
from dataclasses import dataclass
from typing import List

from core.models import Alert

log = logging.getLogger("core.mitigation_engine")


@dataclass
class MitigationAction:
    """
    Data structure representing a proposed mitigation action.
    """
    code: str          # Machine-readable code (e.g., "block_ip")
    label: str         # UI Label (e.g., "Block source IP via firewall")
    description: str   # Detailed human-readable description
    ip_to_block: str | None = None # IP address target for the action, if applicable
    auto_allowed: bool = False  # Whether this action is safe for auto-execution preferences


def suggest_actions_for_alert(alert: Alert) -> List[MitigationAction]:
    """
    Determine recommended mitigation actions for a given Alert.

    This function is pure logic and does not perform any side effects.

    Args:
        alert (Alert): The alert object to analyze.

    Returns:
        List[MitigationAction]: A list of suggested actions.
    """
    actions: List[MitigationAction] = []

    src_ip = getattr(alert, "src_ip", None)
    dst_ip = getattr(alert, "dst_ip", None)
    # severity = (getattr(alert, "severity", "") or "").lower() # Unused
    a_type = (getattr(alert, "alert_type", "") or "").lower()
    msg = (getattr(alert, "message", "") or "").lower()

    # Network attacks
    if src_ip:
        if "port scan" in a_type or "scan" in msg:
            actions.append(
                MitigationAction(
                    code="block_ip",
                    label="Block source IP via firewall",
                    description=f"Add {src_ip} to nftables block set.",
                    ip_to_block=src_ip,
                    auto_allowed=False,
                )
            )

        if "syn flood" in a_type or "flood" in msg:
            actions.append(
                MitigationAction(
                    code="block_ip",
                    label="Temporarily block IP (15 minutes)",
                    description=f"Block {src_ip} for a short time to stop flood traffic.",
                    ip_to_block=src_ip,
                    auto_allowed=True,
                )
            )

        if "sensitive port" in a_type or "reverse shell" in msg:
            # For reverse shell, the THREAT is the destination/outbound IP
            target_ip = dst_ip if "reverse shell" in a_type or "reverse shell" in msg else src_ip
            if target_ip:
                actions.append(
                    MitigationAction(
                        code="block_ip",
                        label=f"Block Access to C2 ({target_ip})",
                        description=f"Block outbound traffic to {target_ip}.",
                        ip_to_block=target_ip,
                        auto_allowed=False,
                    )
                )

    # File / malware alerts
    if "malware" in a_type or "suspicious script" in msg:
        actions.append(
            MitigationAction(
                code="mark_resolved",
                label="Mark as handled",
                description="Mark this alert as resolved after you review and quarantine.",
                ip_to_block=None,
                auto_allowed=False,
            )
        )

    # Fallback
    if not actions:
        actions.append(
            MitigationAction(
                code="mark_resolved",
                label="Mark as resolved",
                description="No automatic mitigation rule matched. Mark as resolved after manual review.",
                ip_to_block=src_ip,
                auto_allowed=False,
            )
        )

    return actions

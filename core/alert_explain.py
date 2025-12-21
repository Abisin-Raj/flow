"""
Alert Explainability Module.

Generates human-readable explanations for alerts, describing:
- What was detected
- Why it's suspicious
- What action was taken
- How the block duration was calculated

This is deterministic and reliable - no ML required.
"""

import logging
from typing import Optional

log = logging.getLogger(__name__)


def explain_alert(alert) -> str:
    """
    Generate a human-readable explanation for an alert.
    
    Args:
        alert: Alert model instance
        
    Returns:
        str: Human-readable explanation text
    """
    parts = []
    
    # What was detected
    alert_type = (alert.alert_type or "unknown activity").replace("_", " ").title()
    parts.append(f"Detected {alert_type}.")
    
    # Severity classification
    severity = (alert.severity or "medium").lower()
    severity_desc = {
        "low": "minor",
        "medium": "moderate",
        "high": "significant",
        "critical": "severe"
    }.get(severity, "moderate")
    parts.append(f"Severity classified as {severity} ({severity_desc} risk).")
    
    # Source IP
    if alert.src_ip:
        parts.append(f"Source IP: {alert.src_ip}.")
    
    # Destination info
    if hasattr(alert, 'dst_ip') and alert.dst_ip:
        parts.append(f"Destination: {alert.dst_ip}.")
    if hasattr(alert, 'dst_port') and alert.dst_port:
        parts.append(f"Port: {alert.dst_port}.")
    
    # Process info if available
    if hasattr(alert, 'process_name') and alert.process_name:
        parts.append(f"Process: {alert.process_name}.")
    
    # Resolution status
    if alert.resolved:
        parts.append("Alert has been resolved by analyst.")
    
    return " ".join(parts)


def explain_block_decision(alert, timeout: int, explanation: dict) -> str:
    """
    Generate explanation for why an IP was blocked with specific duration.
    
    Args:
        alert: Alert model instance
        timeout: Block duration in seconds
        explanation: Explanation dict from calculate_block_timeout
        
    Returns:
        str: Human-readable block decision explanation
    """
    parts = []
    
    # Base decision
    alert_type = (alert.alert_type or "unknown").replace("_", " ")
    parts.append(f"Blocked due to {alert_type}.")
    
    # Duration calculation
    base = explanation.get('severity_base_seconds', 300)
    type_mult = explanation.get('type_multiplier', 1)
    repeat_mult = explanation.get('repeat_multiplier', 1)
    
    calc_parts = []
    calc_parts.append(f"base {base}s from severity")
    
    if type_mult > 1:
        calc_parts.append(f"×{type_mult} for attack type")
    
    if repeat_mult > 1:
        repeat_count = explanation.get('repeat_count', 0)
        calc_parts.append(f"×{repeat_mult} for repeat offender ({repeat_count} recent alerts)")
    
    parts.append(f"Duration: {timeout}s ({', '.join(calc_parts)}).")
    
    # Capped notice
    if explanation.get('capped'):
        parts.append("Duration capped at 24 hours maximum.")
    
    return " ".join(parts)


def get_severity_description(severity: str) -> str:
    """Get human-readable description of severity level."""
    descriptions = {
        "low": "Low severity - reconnaissance or scanning activity. Minimal immediate risk.",
        "medium": "Medium severity - suspicious activity warranting attention. May indicate probing.",
        "high": "High severity - likely attack activity. Immediate investigation recommended.",
        "critical": "Critical severity - active threat or confirmed breach. Immediate action required.",
    }
    return descriptions.get((severity or "").lower(), "Unknown severity level.")

"""
Auto Mitigator Module.

This module automates the response to threats by evaluating the behavior of IPs
based on recent alerts. If an IP exceeds a threat score threshold, it is automatically
blocked via the firewall.
"""

import logging
import ipaddress
from datetime import timedelta
from django.utils import timezone

from core.models import Alert, BlockedIp
from core import settings_api
from core import firewall

log = logging.getLogger("core.auto_mitigator")

BLOCK_THRESHOLD = 5
TRUSTED_PROCESSES = ["chrome", "firefox", "spotify", "slack", "zoom"] # Basic allowlist

def is_valid_block_candidate(ip: str) -> bool:
    """
    Check if an IP address is a valid candidate for auto-blocking.
    
    Excludes:
    - None/Empty IPs
    - Loopback addresses
    - Private IPs (unless configured otherwise)
    - Already blocked IPs

    Args:
        ip (str): IP address to check.

    Returns:
        bool: True if blockable, False otherwise.
    """
    if not ip:
        return False
        
    # check loopback
    if ip in ("127.0.0.1", "::1"):
        return False
        
    try:
        ipobj = ipaddress.ip_address(ip)
        # Check private IPs
        if ipobj.is_private:
            if settings_api.get_bool("block_private_ips") is not True:
                # Default is usually strict, only block public threats
                # But if setting says "block_private_ips=True", we allow it.
                # The user pseudocode check was: 
                # if private and setting!=true: return False
                return False
                
    except ValueError:
        return False

    # Check already blocked (optimization, though helper handles it)
    # Actually we want to catch it to update timestamp or just return 'ignored'
    if BlockedIp.objects.filter(ip=ip).exists():
        # Already blocked
        return False
        
    return True

def recent_alerts(ip: str):
    """
    Retrieve alerts for an IP from the last 60 seconds.
    """
    cutoff = timezone.now() - timedelta(seconds=60)
    return Alert.objects.filter(src_ip=ip, timestamp__gte=cutoff)

def calculate_score(ip: str) -> int:
    """
    Calculate a threat score based on recent activity frequency and type.

    Scoring logic:
    - High volume of alerts (>=5) adds points.
    - Multiple distinct destination ports (>=3) adds points (scanning behavior).
    - Port scan alerts specifically add points.
    - Alerts from untrusted processes add points.

    Args:
        ip (str): IP to score.

    Returns:
        int: Threat score.
    """
    alerts = recent_alerts(ip)
    score = 0
    
    count = alerts.count()
    if count >= 5:
        score += 2
        
    # checking distinct dst_ports
    distinct_ports = alerts.values("dst_port").distinct().count()
    if distinct_ports >= 3:
        score += 2
        
    if alerts.filter(alert_type__icontains="port scan").exists():
        score += 3
        
    # Check for untrusted processes
    # If any alert is NOT from a trusted process (or has no process), score up
    # However, alerts usually track malicious activity which rarely has a trusted process name attached
    # unless it's a compromised browser.
    # The logic: if alerts.exclude(process_name__in=TRUSTED).exists(): score += 2
    if alerts.exclude(process_name__in=TRUSTED_PROCESSES).exists():
        score += 2
        
    return score

def get_block_timeout(ip: str) -> int:
    """
    Determine duration to block an IP based on its block history.
    Progressive discipline: 1st time=1min, 2nd=5mins, 3rd+=30mins.

    Args:
        ip (str): IP address.

    Returns:
        int: Timeout in seconds.
    """
    history = BlockedIp.objects.filter(ip=ip).count()
    
    if history == 0:
        return 60      # 1 min
    if history == 1:
        return 300     # 5 mins
    return 1800        # 30 mins

def evaluate_ip(ip: str) -> str:
    """
    Evaluate an IP for auto-blocking.
    
    If the calculated score exceeds `BLOCK_THRESHOLD`, the IP is blocked
    using the firewall module and recorded in BlockedIp model.

    Args:
        ip (str): IP address to evaluate.

    Returns:
        str: Status ('blocked', 'ignored', 'observed').
    """
    if not is_valid_block_candidate(ip):
        return "ignored"
        
    score = calculate_score(ip)
    
    if score >= BLOCK_THRESHOLD:
        timeout = get_block_timeout(ip)
        log.warning(f"Blocking {ip} (score={score}, timeout={timeout}s)")
        
        ok, msg = firewall.block_ip(ip, timeout_seconds=timeout)
        if ok:
            # Audit log
            BlockedIp.objects.create(ip=ip, reason=f"auto-score-{score}")
            return "blocked"
        else:
            log.error(f"Failed to block {ip}: {msg}")
            return "ignored"
            
    return "observed"

def process_alert(alert: Alert):
    """
    Trigger auto-mitigation checks for a newly created alert.
    
    Uses block_policy to determine appropriate block duration based on:
    - Alert severity
    - Alert type
    - Repeat offender history
    
    This is the hook called by `alert_engine.create_alert_with_geo`.

    Args:
        alert (Alert): The alert instance.
    """
    try:
        # Global switch check
        if not settings_api.firewall_allowed():
            return

        src_ip = alert.src_ip
        if not src_ip:
            return
            
        if not is_valid_block_candidate(src_ip):
            return
        
        # Use block policy for timeout calculation with explanation
        from core.block_policy import calculate_block_timeout, format_explanation
        timeout, explanation = calculate_block_timeout(alert)
        
        log.info(f"Policy-driven block: {src_ip} for {timeout}s | {explanation}")
        
        ok, msg = firewall.block_ip(src_ip, timeout_seconds=timeout)
        if ok:
            # Store explanation in alert message for UI/audit
            explanation_text = format_explanation(explanation)
            alert.message = (alert.message or "") + explanation_text
            alert.save(update_fields=["message"])
            
            BlockedIp.objects.create(
                ip=src_ip, 
                reason=f"policy-{alert.severity or 'medium'}"
            )
            log.info(f"Blocked {src_ip} with explanation stored")
        else:
            log.error(f"Failed to block {src_ip}: {msg}")
            
    except Exception as e:
        log.exception("Error in auto-mitigation: %s", e)

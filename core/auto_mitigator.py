import logging
import ipaddress
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count

from core.models import Alert, BlockedIp, AppSetting
from core import settings_api
from core import mitigation_engine
from core import firewall

log = logging.getLogger("core.auto_mitigator")

BLOCK_THRESHOLD = 5
TRUSTED_PROCESSES = ["chrome", "firefox", "spotify", "slack", "zoom"] # Basic allowlist

def is_valid_block_candidate(ip: str) -> bool:
    """Check if IP is valid for auto-blocking"""
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
    cutoff = timezone.now() - timedelta(seconds=60)
    return Alert.objects.filter(src_ip=ip, timestamp__gte=cutoff)

def calculate_score(ip: str) -> int:
    """Calculate threat score based on recent activity"""
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
    """Progressive timeout based on history"""
    history = BlockedIp.objects.filter(ip=ip).count()
    
    if history == 0:
        return 60      # 1 min
    if history == 1:
        return 300     # 5 mins
    return 1800        # 30 mins

def evaluate_ip(ip: str) -> str:
    """
    Main entry point for decision.
    Returns: 'blocked', 'ignored', 'observed'
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
    Called by alert_engine after saving a new alert.
    """
    try:
        # Global switch check
        if not settings_api.firewall_allowed():
            return

        src_ip = alert.src_ip
        if src_ip:
            evaluate_ip(src_ip)
            
    except Exception as e:
        log.exception("Error in auto-mitigation: %s", e)

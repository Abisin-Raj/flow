"""
Firewall Client Module.

This module provides a client interface to interact with the privileged firewall helper.
It communicates via a Unix domain socket to request IP blocking/unblocking and status checks.
It implements exponential backoff for resilience.
"""

import socket
import logging
import os
import time
from typing import Tuple, List, Optional
from functools import wraps

log = logging.getLogger("core.firewall")

# Socket configuration - Must match server settings
SOCKET_PATH = "/run/flow/firewall.sock"
SOCKET_TIMEOUT = 5.0  # seconds
MAX_RESPONSE_LENGTH = 4096
# Retry settings
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0  # seconds
MAX_BACKOFF = 30.0  # seconds

# Health check state
_last_health_check = 0
_health_check_interval = 60  # seconds
_helper_available = None  # None = unknown, True = available, False = unavailable


def exponential_backoff_retry(max_retries=MAX_RETRIES):
    """
    Decorator for retry logic with exponential backoff.
    
    If the decorated function raises ConnectionRefusedError, FileNotFoundError, or socket.timeout,
    it retries up to `max_retries` with increasing wait times.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            backoff = INITIAL_BACKOFF
            last_error = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (ConnectionRefusedError, FileNotFoundError, socket.timeout) as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        wait_time = min(backoff * (2 ** attempt), MAX_BACKOFF)
                        log.warning(f"Firewall helper unavailable, retrying in {wait_time:.1f}s (attempt {attempt + 1}/{max_retries})")
                        time.sleep(wait_time)
                    else:
                        log.error(f"Firewall helper unavailable after {max_retries} attempts")
            
            # All retries failed
            raise last_error
        return wrapper
    return decorator


@exponential_backoff_retry(max_retries=MAX_RETRIES)
def _send_firewall_command(command: str) -> Tuple[bool, str]:
    """
    Send command to firewall helper via Unix socket with retry logic.
    
    Args:
        command (str): The raw text command to send.
        
    Returns:
        tuple: (success: bool, response_or_error: str)
    """
    if not os.path.exists(SOCKET_PATH):
        raise FileNotFoundError(f"Firewall helper socket not found at {SOCKET_PATH}")
    
    # Connect to Unix socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    
    try:
        sock.connect(SOCKET_PATH)
        
        # Send command
        sock.sendall((command + '\n').encode('utf-8'))
        
        # Receive response
        response = sock.recv(MAX_RESPONSE_LENGTH).decode('utf-8').strip()
        
        # Parse response
        if response.startswith("OK"):
            return True, response[3:].strip()  # Remove "OK " prefix
        elif response.startswith("ERROR"):
            error_msg = response[6:].strip()  # Remove "ERROR " prefix
            log.warning("Firewall command failed: %s", error_msg)
            return False, error_msg
        else:
            log.warning("Unexpected response from firewall helper: %s", response)
            return False, "Unexpected response format"
    finally:
        sock.close()


def is_firewall_available() -> bool:
    """
    Check if firewall helper is running and responsive.
    
    Uses a simple short-term cache to avoid spamming sockets on repeated calls.
    Returns cached result if within `_health_check_interval`.
    
    Returns:
        bool: True if available, False otherwise.
    """
    global _last_health_check, _helper_available
    
    now = time.time()
    
    # Return cached result if fresh
    if _helper_available is not None and (now - _last_health_check) < _health_check_interval:
        return _helper_available
    
    # Perform health check
    if not os.path.exists(SOCKET_PATH):
        _helper_available = False
        _last_health_check = now
        return False
    
    try:
        ok, _ = _send_firewall_command("STATUS")
        _helper_available = ok
        _last_health_check = now
        return ok
    except Exception as e:
        log.debug(f"Health check failed: {e}")
        _helper_available = False
        _last_health_check = now
        return False


# Severity to timeout mapping (seconds)
SEVERITY_TIMEOUTS = {
    "low": 60,         # 1 min for reconnaissance
    "medium": 300,     # 5 mins for suspicious
    "high": 1800,      # 30 mins for attack
    "critical": 3600,  # 1 hour for active threat
}

# ... (exponential_backoff_retry and _send_firewall_command remain same) ...

def block_ip(ip: str, severity: str = "medium", timeout_seconds: Optional[int] = None) -> Tuple[bool, str]:
    """
    Block an IP address via firewall helper with automatic retry.
    
    Args:
        ip: IP address to block.
        severity: Alert severity level (low, medium, high, critical) to determine timeout.
        timeout_seconds: Optional explicit timeout overrides severity default.
    
    Returns:
        (success, error_message)
    """
    # Layer 1: Protected IP guard - refuse to block critical system IPs
    from core.protected_ips import is_protected_ip, get_protection_reason
    if is_protected_ip(ip):
        reason = get_protection_reason(ip)
        log.warning(f"Refused to block protected IP: {ip} ({reason})")
        return False, f"Protected IP refused: {reason}"
    
    # Determine timeout
    if timeout_seconds is None:
        timeout_seconds = SEVERITY_TIMEOUTS.get(severity.lower(), 300)
    
    # Dry-run mode: log decision but don't actually block
    from core import settings_api
    if settings_api.is_firewall_dry_run():
        log.warning(
            "DRY-RUN: would block ip=%s timeout=%ss severity=%s",
            ip, timeout_seconds, severity
        )
        return True, "Dry-run: block simulated"
    
    log.info("block_ip called for %s (severity=%s, timeout=%s)", ip, severity, timeout_seconds)
    
    # Simple reason mapping based on severity, strictly alphanumeric for helper
    reason_map = {
        "low": "reconnaissance",
        "medium": "suspicious_activity",
        "high": "confirmed_attack",
        "critical": "active_threat",
    }
    reason = reason_map.get(severity.lower(), "manual_block")
    
    # Build command
    command = f"BLOCK_IP {ip} {reason} {timeout_seconds}"
    
    try:
        ok, response = _send_firewall_command(command)
        
        if ok:
            # Store block record with expiration time
            from datetime import timedelta
            from django.utils import timezone
            from core.models import BlockedIp
            
            expires = timezone.now() + timedelta(seconds=timeout_seconds)
            BlockedIp.objects.update_or_create(
                ip=ip,
                defaults={
                    "expires_at": expires,
                    "reason": reason
                }
            )
            
            log.info("Successfully blocked IP: %s (expires: %s)", ip, expires)
            return True, ""
        else:
            return False, response
    except Exception as e:
        log.error(f"Failed to block IP {ip}: {e}")
        return False, f"Helper unavailable: {e}"


def unblock_ip(ip: str) -> Tuple[bool, str]:
    """
    Unblock an IP address via firewall helper with automatic retry.
    
    Args:
        ip: IP address to unblock
    
    Returns:
        (success, error_message)
    """
    log.info("unblock_ip called for %s", ip)
    
    command = f"UNBLOCK_IP {ip}"
    
    try:
        ok, response = _send_firewall_command(command)
        
        if ok:
            log.info("Successfully unblocked IP: %s", ip)
            return True, ""
        else:
            return False, response
    except Exception as e:
        log.error(f"Failed to unblock IP {ip}: {e}")
        return False, f"Helper unavailable: {e}"


def get_blocked_ips() -> List[str]:
    """
    Get list of currently blocked IPs from firewall helper with automatic retry.
    
    Returns:
        List of IP address strings
    """
    command = "LIST_BLOCKED"
    
    try:
        ok, response = _send_firewall_command(command)
        
        if ok:
            # Success - response may be empty if no IPs are blocked
            if response:
                ips = [ip.strip() for ip in response.split(',') if ip.strip()]
                return ips
            else:
                # Empty list is valid, not an error
                return []
        else:
            # Actual error from helper
            log.warning("Failed to get blocked IPs: %s", response)
            return []
    except Exception as e:
        log.warning(f"Failed to get blocked IPs: {e}")
        return []


# Legacy compatibility functions (no-op, for backward compatibility)
def ensure_table() -> bool:
    """Legacy function - now handled by firewall helper"""
    return is_firewall_available()


def ensure_chain() -> bool:
    """Legacy function - now handled by firewall helper"""
    return is_firewall_available()


def ensure_set() -> bool:
    """Legacy function - now handled by firewall helper"""
    return is_firewall_available()


def ensure_drop_rule() -> bool:
    """Legacy function - now handled by firewall helper"""
    return is_firewall_available()


def add_ip_to_block_set(ip: str, timeout_seconds: Optional[int] = None) -> Tuple[bool, str]:
    """Legacy function - redirects to block_ip"""
    return block_ip(ip, timeout_seconds)


def reconcile_firewall_state():
    """
    Sync kernel nftables state with PostgreSQL BlockedIp table.
    
    Kernel state is authoritative. This should be called on app startup
    to ensure database matches actual firewall rules.
    
    Rules:
    - If IP exists in nftables but not DB → insert into DB
    - If IP exists in DB but not nftables → delete from DB
    - Never auto-block new IPs from DB alone
    """
    from django.db import transaction
    from core.models import BlockedIp
    
    if not is_firewall_available():
        log.warning("Firewall helper not available, skipping reconciliation")
        return
    
    try:
        # Get all blocked IPs from kernel (via helper)
        nft_ips = set(get_blocked_ips())
        
        with transaction.atomic():
            # Get all IPs in database
            db_ips = set(BlockedIp.objects.values_list("ip", flat=True))
            
            # Kernel → DB (missing rows): add IPs that are in nftables but not in DB
            for ip in nft_ips - db_ips:
                BlockedIp.objects.create(
                    ip=ip,
                    reason="reconciled_from_kernel",
                )
                log.info(f"Reconciliation: added {ip} to DB (was in kernel only)")
            
            # DB → cleanup (stale rows): remove IPs that are in DB but not in nftables
            stale_ips = db_ips - nft_ips
            if stale_ips:
                deleted_count = BlockedIp.objects.filter(ip__in=stale_ips).delete()[0]
                log.info(f"Reconciliation: removed {deleted_count} stale entries from DB")
        
        log.info(f"Firewall reconciliation complete: {len(nft_ips)} IPs in kernel, DB synced")
        
    except Exception as e:
        log.exception(f"Error during firewall reconciliation: {e}")

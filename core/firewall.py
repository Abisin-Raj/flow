import socket
import logging
import os
import time
from typing import Tuple, List, Optional
from functools import wraps

log = logging.getLogger("core.firewall")

# Socket configuration
SOCKET_PATH = "/run/flow/firewall.sock"
SOCKET_TIMEOUT = 5.0  # seconds
MAX_RESPONSE_LENGTH = 4096
MAX_RETRIES = 3
INITIAL_BACKOFF = 1.0  # seconds
MAX_BACKOFF = 30.0  # seconds

# Health check state
_last_health_check = 0
_health_check_interval = 60  # seconds
_helper_available = None  # None = unknown, True = available, False = unavailable


def exponential_backoff_retry(max_retries=MAX_RETRIES):
    """Decorator for retry logic with exponential backoff"""
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
    Returns (success, response_or_error)
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
    Check if firewall helper is running and responsive with caching.
    Uses cached result unless cache is expired.
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


def block_ip(ip: str, timeout_seconds: Optional[int] = None) -> Tuple[bool, str]:
    """
    Block an IP address via firewall helper with automatic retry.
    
    Args:
        ip: IP address to block
        timeout_seconds: Optional timeout in seconds (1-86400)
    
    Returns:
        (success, error_message)
    """
    log.info("block_ip called for %s (timeout=%s)", ip, timeout_seconds)
    
    # Build command
    reason = "blocked_by_flow"
    if timeout_seconds:
        command = f"BLOCK_IP {ip} {reason} {timeout_seconds}"
    else:
        command = f"BLOCK_IP {ip} {reason}"
    
    try:
        ok, response = _send_firewall_command(command)
        
        if ok:
            log.info("Successfully blocked IP: %s", ip)
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



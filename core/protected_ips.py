"""
Protected IP Module.

Provides safeguards to prevent Flow from blocking critical system IPs:
- Loopback addresses (127.0.0.1, ::1)
- Link-local addresses
- Multicast addresses
- Reserved / special addresses
- Default gateway
- Local DNS resolvers

This is a mandatory safety layer that cannot be bypassed.
"""

import ipaddress
import subprocess
import logging

log = logging.getLogger(__name__)

# Cache gateway and DNS (refreshed on each call, but could be cached)
_gateway_cache = None
_dns_cache = None


def get_default_gateway_ips() -> set:
    """
    Get the system's default gateway IP addresses.
    Works for both IPv4 and IPv6.
    """
    gateways = set()
    try:
        # IPv4 gateway
        output = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in output.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    gateways.add(parts[idx + 1])
    except Exception:
        pass

    try:
        # IPv6 gateway
        output = subprocess.run(
            ["ip", "-6", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in output.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    gateways.add(parts[idx + 1])
    except Exception:
        pass

    return gateways


def get_dns_resolvers() -> set:
    """
    Get the system's configured DNS resolver IP addresses.
    """
    resolvers = set()
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        resolvers.add(parts[1])
    except Exception:
        pass

    return resolvers


def is_protected_ip(ip: str) -> bool:
    """
    Check if an IP address is protected and should never be blocked.
    
    Protected IPs include:
    - Loopback (127.0.0.0/8, ::1)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Reserved addresses
    - Unspecified (0.0.0.0, ::)
    - Default gateway
    - DNS resolvers
    
    Args:
        ip: IP address string to check
        
    Returns:
        bool: True if IP is protected, False if safe to block
    """
    if not ip:
        return True  # Empty = protected (don't block nothing)

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        log.warning(f"Invalid IP address: {ip}")
        return True  # Invalid IP = treat as protected (fail safe)

    # Built-in protections from ipaddress module
    if ip_obj.is_loopback:
        log.debug(f"Protected: {ip} is loopback")
        return True

    if ip_obj.is_link_local:
        log.debug(f"Protected: {ip} is link-local")
        return True

    if ip_obj.is_multicast:
        log.debug(f"Protected: {ip} is multicast")
        return True

    if ip_obj.is_reserved:
        log.debug(f"Protected: {ip} is reserved")
        return True

    if ip_obj.is_unspecified:
        log.debug(f"Protected: {ip} is unspecified (0.0.0.0 or ::)")
        return True

    # Gateway protection
    gateways = get_default_gateway_ips()
    if ip in gateways:
        log.debug(f"Protected: {ip} is default gateway")
        return True

    # DNS protection
    resolvers = get_dns_resolvers()
    if ip in resolvers:
        log.debug(f"Protected: {ip} is DNS resolver")
        return True

    return False


def get_protection_reason(ip: str) -> str:
    """
    Get human-readable reason why an IP is protected.
    Returns empty string if not protected.
    """
    if not ip:
        return "empty address"

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid address"

    if ip_obj.is_loopback:
        return "loopback address"
    if ip_obj.is_link_local:
        return "link-local address"
    if ip_obj.is_multicast:
        return "multicast address"
    if ip_obj.is_reserved:
        return "reserved address"
    if ip_obj.is_unspecified:
        return "unspecified address"
    if ip in get_default_gateway_ips():
        return "default gateway"
    if ip in get_dns_resolvers():
        return "DNS resolver"

    return ""

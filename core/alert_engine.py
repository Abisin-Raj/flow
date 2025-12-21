"""
Alert Engine Module.

This module acts as the central hub for creating, processing, and saving alerts.
It handles:
1.  Mapping alert data to the database model.
2.  Enriching alerts with geolocation data.
3.  Classifying network scans (fast, brute, stealth).
4.  Triggering auto-mitigation actions upon alert creation.
"""

import logging
import time
from ipaddress import ip_address
from django.utils import timezone

from core.models import Alert, Connection
from core.geolocation import get_geo as lookup_ip
from core import settings_api

log = logging.getLogger("core.alert_engine")


def _get_field_map():
    """
    Map logical names to model fields.
    """
    model_fields = {f.name for f in Alert._meta.get_fields() if hasattr(f, "name")}

    def find(*candidates):
        for c in candidates:
            if c in model_fields:
                return c
        return None

    return {
        "time": find("timestamp", "time", "created_at", "created", "ts"),
        "src": find("src_ip", "source_ip", "source", "src"),
        "dst": find("dst_ip", "destination_ip", "destination", "dst"),
        "proto": find("protocol", "proto"),
        "severity": find("severity", "level"),
        "status": find("status", "state"),
        "message": find("message", "reason", "note"),
    }


def classify_scan(src_ip: str, events: list, now_ts: float = None):
    """
    Classify the type of network scan based on the timing and pattern of events.

    Args:
        src_ip (str): The source IP address performing the scan.
        events (list): A list of tuples (timestamp, port).
        now_ts (float, optional): Current timestamp.

    Returns:
        str: One of 'fast', 'brute', 'stealth', 'local', or 'unknown'.
    """
    if now_ts is None:
        now_ts = time.time()
    if not src_ip or not events:
        return "unknown"

    cutoff_10 = now_ts - 10
    ports_10 = {p for t, p in events if t >= cutoff_10}

    cutoff_30 = now_ts - 30
    events_30 = [(t, p) for t, p in events if t >= cutoff_30]
    ports_30 = {p for t, p in events_30}

    cutoff_300 = now_ts - 300
    events_300 = [(t, p) for t, p in events if t >= cutoff_300]
    ports_300 = {p for t, p in events_300}

    if len(ports_10) > 100:
        return "fast"

    if len(events_30) >= 10 and len(ports_30) == 1:
        return "brute"

    if len(events_300) >= 6 and len(ports_300) <= 5:
        sorted_ports = sorted(ports_300)
        seq_count = 0
        for i in range(1, len(sorted_ports)):
            if sorted_ports[i] - sorted_ports[i - 1] == 1:
                seq_count += 1
        if seq_count >= 2 or any(p < 1024 for p in ports_300):
            return "stealth"

    try:
        ipobj = ip_address(src_ip)
        if ipobj.is_private:
            return "local"
    except Exception as e:
        log.warning(f"Failed to parse IP {src_ip} for classification: {e}")
        pass

    return "unknown"


def create_alert_with_geo(
    src_ip: str | None = None,
    message: str = "",
    severity: str = "medium",
    category: str | None = None,
    alert_type: str | None = None,
    connection: Connection | None = None,
    **kwargs,
) -> Alert | None:
    """
    Create, save, and process a new alert.

    This function performs several key steps:
    1.  Checks if the IP is ignored (allowlisted/private).
    2.  Instantiates an Alert model.
    3.  Populates standard fields (src_ip, message, severity, etc.).
    4.  Populates extra fields via kwargs.
    5.  Performs Geolocation lookup to add country/city/lat/lon.
    6.  Saves the alert to the database.
    7.  Triggers the auto-mitigator to potentially block the IP.

    Args:
        src_ip (str): Source IP address.
        message (str): Alert description.
        severity (str): Alert severity (low, medium, high, critical).
        category (str): Alert category (e.g., port scan, malware).
        alert_type (str): Specific type string.
        connection (Connection): Related Connection object if any.
        **kwargs: Additional fields to map to the Alert model.

    Returns:
        Alert: The saved Alert object, or None if creation failed or IP was ignored.
    """
    # Check if this IP should be ignored based on global settings
    if src_ip and settings_api.is_ip_ignored(src_ip):
        # skip trusted or local IPs
        return None

    try:
        alert = Alert()
    except Exception:
        log.exception("Failed to instantiate Alert model")
        return None

    # basic fields
    try:
        if hasattr(alert, "src_ip") and src_ip:
            alert.src_ip = src_ip
        if hasattr(alert, "message"):
            alert.message = message
        if hasattr(alert, "severity"):
            alert.severity = severity
        if hasattr(alert, "category") and category is not None:
            alert.category = category
        if hasattr(alert, "alert_type") and alert_type is not None:
            alert.alert_type = alert_type
        if hasattr(alert, "connection") and connection is not None:
            alert.connection = connection
    except Exception:
        log.exception("Failed to set base alert fields")

    # copy extra kwargs into model if matching fields exist
    for k, v in kwargs.items():
        try:
            if hasattr(alert, k):
                setattr(alert, k, v)
        except Exception as e:
            log.error(f"Error setting alert field {k}: {e}")
            continue

    # timestamp fallback
    try:
        if hasattr(alert, "timestamp") and not getattr(alert, "timestamp", None):
            alert.timestamp = timezone.now()
    except Exception as e:
        log.warning(f"Failed to set timestamp on alert: {e}")
        pass

    # geo lookup if possible
    if src_ip:
        try:
            geo = lookup_ip(src_ip)
        except Exception:
            geo = None

        if geo:
            try:
                if hasattr(alert, "src_country") and "country" in geo:
                    alert.src_country = geo.get("country", "")
                if hasattr(alert, "src_city") and "city" in geo:
                    alert.src_city = geo.get("city", "")
                if hasattr(alert, "latitude") and "lat" in geo:
                    alert.latitude = geo.get("lat")
                if hasattr(alert, "longitude") and "lon" in geo:
                    alert.longitude = geo.get("lon")
            except Exception:
                log.exception("Failed to set geo fields on alert")

    # Handle proc_name and add debug logging
    proc_name = kwargs.get("proc_name", None)
    try:
        log.debug(
            "Saving alert src=%s dst=%s port=%s proc=%s msg=%s",
            src_ip,
            getattr(alert, "dst_ip", None),
            getattr(alert, "dst_port", None),
            proc_name,
            message,
        )
        if proc_name and hasattr(alert, "proc_name"):
            alert.proc_name = proc_name
    except Exception as e:
        log.debug("Failed to set proc_name: %s", e)

    try:
        alert.save()
        # Trigger auto-mitigation
        from core import auto_mitigator
        auto_mitigator.process_alert(alert)
    except Exception:
        log.exception("Failed to save or process Alert")
        return None

    return alert


def create_alert_for_connection(
    src_ip=None, dst_ip=None, dst_port=None, message=None, severity=None, **extra
):
    """
    Wrapper for `create_alert_with_geo` to support legacy call signatures involving specific connection details.

    It normalizes field names (e.g., `dstport` -> `dst_port`) and handles
    process-specific fields like PID and process name.

    Args:
        src_ip (str): Source IP.
        dst_ip (str): Destination IP.
        dst_port (int): Destination Port.
        message (str): Alert message.
        severity (str): Severity level.
        **extra: Additional arguments passed to `create_alert_with_geo`.

    Returns:
        Alert: The created alert object.
    """
    payload = {}
    if src_ip is not None:
        payload["src_ip"] = src_ip
    if dst_ip is not None:
        payload["dst_ip"] = dst_ip
    if dst_port is not None:
        payload["dst_port"] = dst_port
        payload["dstport"] = dst_port
        payload["port"] = dst_port
    if message is not None:
        payload["message"] = message
    if severity is not None:
        payload["severity"] = severity

    pid = extra.pop("pid", None)
    if pid is not None:
        payload["pid"] = pid

    proc_name = extra.pop("process_name", None)
    if proc_name is not None:
        payload["process_name"] = proc_name

    payload.update(extra)
    return create_alert_with_geo(**payload)

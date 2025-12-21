"""
Export Service.

This module provides high-level functions to export bulk data (Alerts, Connections)
to CSV files in the user's `~/.flow_exports` directory.
It is primarily used by the 'Admin / Export' widgets.
"""

from pathlib import Path

from django.utils import timezone

from core.models import Alert, Connection


def _export_dir() -> Path:
    """Get or create the export directory."""
    base = Path.home() / ".flow_exports"
    base.mkdir(parents=True, exist_ok=True)
    return base


def export_alerts_to_csv(limit: int = 5000) -> Path:
    """
    Export the most recent alerts to a CSV file.

    Args:
        limit (int): Max number of records to export.

    Returns:
        Path: The absolute path to the generated CSV file.
    """
    out_dir = _export_dir()
    ts = timezone.now().strftime("%Y%m%d%H%M%S")
    path = out_dir / f"alerts_{ts}.csv"

    qs = Alert.objects.order_by("-id")[:limit]
    rows = []

    # pick common fields that usually exist
    headers = [
        "id",
        "time",
        "src_ip",
        "dst_ip",
        "dst_port",
        "severity",
        "category",
        "alert_type",
        "message",
    ]

    for a in qs:
        time_val = getattr(a, "timestamp", None) or getattr(a, "time", None)
        if time_val:
            try:
                time_val = timezone.localtime(time_val)
                time_str = time_val.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                time_str = str(time_val)
        else:
            time_str = ""

        row = {
            "id": getattr(a, "id", ""),
            "time": time_str,
            "src_ip": getattr(a, "src_ip", ""),
            "dst_ip": getattr(a, "dst_ip", ""),
            "dst_port": getattr(a, "dst_port", ""),
            "severity": getattr(a, "severity", ""),
            "category": getattr(a, "category", ""),
            "alert_type": getattr(a, "alert_type", ""),
            "message": getattr(a, "message", ""),
        }
        rows.append(row)

    with path.open("w", encoding="utf-8") as f:
        f.write(",".join(headers) + "\n")
        for r in rows:
            parts = []
            for h in headers:
                val = str(r.get(h, "")).replace('"', '""')
                if "," in val or '"' in val or "\n" in val:
                    val = f'"{val}"'
                parts.append(val)
            f.write(",".join(parts) + "\n")

    return path


def export_connections_to_csv(limit: int = 10000) -> Path:
    """
    Export the most recent connections to a CSV file.

    Args:
        limit (int): Max number of records to export.

    Returns:
        Path: The absolute path to the generated CSV file.
    """
    out_dir = _export_dir()
    ts = timezone.now().strftime("%Y%m%d%H%M%S")
    path = out_dir / f"connections_{ts}.csv"

    qs = Connection.objects.order_by("-timestamp")[:limit]
    rows = []

    headers = [
        "id",
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "status",
    ]

    for c in qs:
        time_val = getattr(c, "timestamp", None)
        if time_val:
            try:
                time_val = timezone.localtime(time_val)
                time_str = time_val.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                time_str = str(time_val)
        else:
            time_str = ""

        row = {
            "id": getattr(c, "id", ""),
            "timestamp": time_str,
            "src_ip": getattr(c, "src_ip", ""),
            "src_port": getattr(c, "src_port", ""),
            "dst_ip": getattr(c, "dst_ip", ""),
            "dst_port": getattr(c, "dst_port", ""),
            "protocol": getattr(c, "protocol", ""),
            "status": getattr(c, "status", ""),
        }
        rows.append(row)

    with path.open("w", encoding="utf-8") as f:
        f.write(",".join(headers) + "\n")
        for r in rows:
            parts = []
            for h in headers:
                val = str(r.get(h, "")).replace('"', '""')
                if "," in val or '"' in val or "\n" in val:
                    val = f'"{val}"'
                parts.append(val)
            f.write(",".join(parts) + "\n")

    return path

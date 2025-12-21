"""
CSV Logger Module.

This module handles the continuous logging of high-severity alerts to daily CSV files.
This provides a persistent, rotation-friendly log format outside the main database.
"""

import os
import csv
from pathlib import Path
from datetime import datetime


CSV_DIR = Path(os.path.expanduser("~/.flow_csv"))


def ensure_csv_dir() -> Path:
    """Ensure the CSV logging directory exists."""
    CSV_DIR.mkdir(parents=True, exist_ok=True)
    return CSV_DIR


def get_daily_csv_path(prefix: str = "high_alerts") -> Path:
    """
    Get the file path for today's log file.
    Format: ~/.flow_csv/{prefix}_{YYYY_MM_DD}.csv
    """
    ensure_csv_dir()
    today = datetime.now().strftime("%Y_%m_%d")
    filename = f"{prefix}_{today}.csv"
    return CSV_DIR / filename


def append_high_alert_to_csv(alert_obj, field_map: dict):
    """
    Append a single 'high' severity alert to today's CSV file.
    
    This function manually constructs the CSV row to ensure control over
    field formatting and error handling.

    Args:
        alert_obj (Alert): The alert instance to log.
        field_map (dict): Mapping of CSV headers to Alert model fields.
    """
    csv_path = get_daily_csv_path()

    time_field = field_map.get("time")
    src_field = field_map.get("src")
    dst_field = field_map.get("dst")
    proto_field = field_map.get("proto")
    status_field = field_map.get("status")
    severity_field = field_map.get("severity")
    message_field = field_map.get("message")

    def get_value(field_name):
        if not field_name:
            return ""
        val = getattr(alert_obj, field_name, "")
        if val is None:
            return ""
        return val

    time_val = get_value(time_field)
    if hasattr(time_val, "strftime"):
        time_val = time_val.strftime("%Y-%m-%d %H:%M:%S")

    row = {
        "time": time_val,
        "src_ip": get_value(src_field),
        "dst_ip": get_value(dst_field),
        "protocol": get_value(proto_field),
        "status": get_value(status_field),
        "severity": get_value(severity_field),
        "message": get_value(message_field),
    }

    file_exists = csv_path.exists()

    with csv_path.open("a", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "time",
                "src_ip",
                "dst_ip",
                "protocol",
                "status",
                "severity",
                "message",
            ],
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

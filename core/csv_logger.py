import os
import csv
from pathlib import Path
from datetime import datetime


CSV_DIR = Path(os.path.expanduser("~/.flow_csv"))


def ensure_csv_dir() -> Path:
    CSV_DIR.mkdir(parents=True, exist_ok=True)
    return CSV_DIR


def get_daily_csv_path(prefix: str = "high_alerts") -> Path:
    ensure_csv_dir()
    today = datetime.now().strftime("%Y_%m_%d")
    filename = f"{prefix}_{today}.csv"
    return CSV_DIR / filename


def append_high_alert_to_csv(alert_obj, field_map: dict):
    """
    Append a single 'high' severity alert to today's CSV file.
    Uses field_map from _get_field_map to extract values.
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

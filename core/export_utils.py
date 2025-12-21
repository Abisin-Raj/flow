"""
Export Utilities.

Helper functions for serializing QuerySets to CSV or JSON.
Used by the UI for generating downloadable reports.
"""

import csv
import json
from typing import List
from django.utils import timezone


def _serialize_value(val):
    """
    Convert a model field value to a string suitable for CSV/JSON.
    Handles Datetime objects by converting them to local time.
    """
    if val is None:
        return ""
    try:
        from datetime import datetime

        if isinstance(val, datetime):
            try:
                val = timezone.localtime(val)
            except Exception:
                pass
            return val.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return str(val)


def export_query_to_csv(qs, field_names: List[str], file_path: str):
    """
    Write a Django QuerySet to a CSV file.

    Args:
        qs (QuerySet): Source data.
        field_names (list): List of attribute names to export.
        file_path (str): Destination file path.
    """
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(field_names)
        for obj in qs:
            row = []
            for name in field_names:
                val = getattr(obj, name, "")
                row.append(_serialize_value(val))
            writer.writerow(row)


def export_query_to_json(qs, field_names: List[str], file_path: str):
    """
    Write a Django QuerySet to a JSON file.

    Args:
        qs (QuerySet): Source data.
        field_names (list): List of attribute names to export.
        file_path (str): Destination file path.
    """
    data = []
    for obj in qs:
        item = {}
        for name in field_names:
            val = getattr(obj, name, "")
            item[name] = _serialize_value(val)
        data.append(item)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_alerts_csv(qs, file_path: str):
    """
    Convenience wrapper for Alert objects.
    """
    fields = [
        "id",
        "src_ip",
        "dst_ip",
        "dst_port",
        "severity",
        "category",
        "alert_type",
        "status",
        "message",
    ]
    export_query_to_csv(qs, fields, file_path)


def export_alerts_json(qs, file_path: str):
    fields = [
        "id",
        "src_ip",
        "dst_ip",
        "dst_port",
        "severity",
        "category",
        "alert_type",
        "status",
        "message",
    ]
    export_query_to_json(qs, fields, file_path)


def export_connections_csv(qs, file_path: str):
    """
    Convenience wrapper for Connection objects.
    """
    fields = [
        "id",
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "status",
    ]
    export_query_to_csv(qs, fields, file_path)

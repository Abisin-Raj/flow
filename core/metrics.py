# File: core/metrics.py

from datetime import datetime, timezone
from django.db.models import Q
from core.models import Alert

# quarantined file model is optional in some schemas
try:
    from core.models import QuarantinedFile
except Exception:
    QuarantinedFile = None


def _start_of_day_utc():
    now = datetime.now(timezone.utc)
    return datetime(now.year, now.month, now.day, tzinfo=timezone.utc)


def connections_today():
    """
    Return number of connection records created since start of today UTC.
    Uses the Connection model as the source of truth for "connections".
    """
    from datetime import datetime, timezone
    from core.models import Connection

    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    try:
        return Connection.objects.filter(timestamp__gte=start).count()
    except Exception:
        # fallback: 0 if the model is missing or DB error
        return 0


def high_alerts_count(severity_threshold=7):
    """
    Count alerts with severity numeric or textual above threshold.
    If severity stored as text, look for keywords 'high' or 'critical'.
    """
    # numeric severity
    q_num = Q()
    try:
        q_num = Q(severity__gte=severity_threshold)
    except Exception:
        q_num = Q()

    # textual severity
    q_text = Q(severity__icontains="high") | Q(severity__icontains="critical")

    return Alert.objects.filter(q_num | q_text).count()


def quarantines_count():
    """
    Return number of quarantined files if model exists, otherwise 0.
    """
    if QuarantinedFile is None:
        return 0
    try:
        return QuarantinedFile.objects.count()
    except Exception:
        return 0


def dashboard_metrics():
    """
    Return a dict with counts:
      connections_today, high_alerts, quarantines
    """
    return {
        "connections_today": connections_today(),
        "high_alerts": high_alerts_count(),
        "quarantines": quarantines_count(),
    }

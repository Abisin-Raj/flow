from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from core.models import Connection, Alert


class Command(BaseCommand):
    help = "Delete old Connection and Alert records to keep the database small."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=7,
            help="Number of days to keep. Older rows are deleted. Default is 7.",
        )

    def handle(self, *args, **options):
        days = options["days"]
        cutoff = timezone.now() - timedelta(days=days)

        # Delete Connections
        conn_qs = Connection.objects.filter(timestamp__lt=cutoff)
        del_conn, _ = conn_qs.delete()

        # Delete Alerts
        alert_qs = Alert.objects.filter(timestamp__lt=cutoff)
        del_alert, _ = alert_qs.delete()

        self.stdout.write(
            f"Deleted {del_conn} Connection rows and {del_alert} Alert rows older than {days} days."
        )

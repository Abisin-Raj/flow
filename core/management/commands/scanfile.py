from django.core.management.base import BaseCommand
from core.file_scan_service import scan_and_record


class Command(BaseCommand):
    help = "Scan a single file and optionally quarantine it"

    def add_arguments(self, parser):
        parser.add_argument("path", type=str, help="Path to file to scan")
        parser.add_argument(
            "--no-quarantine",
            action="store_true",
            help="Do not move the file, only log the scan result",
        )

    def handle(self, *args, **options):
        path = options["path"]
        no_quarantine = options["no_quarantine"]

        data = scan_and_record(path, auto_quarantine=not no_quarantine)

        self.stdout.write(f"Scanning: {path}")
        # self.stdout.write(f"Type: {data.get('file_type', 'unknown')}")
        self.stdout.write(f"Hash: {data.get('sha256', '')}")
        self.stdout.write(f"Malicious: {data.get('is_malicious', False)}")
        self.stdout.write(f"Reason: {data.get('reason', '')}")

        # if data.get("quarantine_path"):
        #     self.stdout.write(f"Quarantined to: {data['quarantine_path']}")

        # self.stdout.write(f"Quarantine entry id={data.get('db_id')}")

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction, DatabaseError
from core.models import Connection, Alert, QuarantinedFile
import random
import hashlib


class Command(BaseCommand):
    help = "Insert sample connections, alerts, and quarantined files"

    def handle(self, *args, **options):
        self.stdout.write("Seeding fake data...")

        try:
            with transaction.atomic():

                # 1. Sample connections
                for i in range(10):
                    c = Connection.objects.create(
                        src_ip=f"192.168.1.{random.randint(10, 200)}",
                        src_port=random.randint(1024, 65535),
                        dst_ip=random.choice(["8.8.8.8", "1.1.1.1", "104.26.10.78"]),
                        dst_port=random.choice([80, 443, 22, 53]),
                        protocol=random.choice(["tcp", "udp"]),
                        status="ESTABLISHED",
                    )

                    # 2. Create alerts for every second connection
                    if i % 2 == 0:
                        Alert.objects.create(
                            alert_type="suspicious_connection",
                            severity=random.choice(["low", "medium", "high"]),
                            message=f"Suspicious traffic detected from {c.src_ip}",
                            connection=c,
                        )

                # 3. Quarantined files
                for j in range(3):
                    filename = f"suspicious_{j}.bin"
                    fake_content = f"fake-data-{random.random()}".encode("utf-8")
                    sha = hashlib.sha256(fake_content).hexdigest()

                    QuarantinedFile.objects.create(
                        original_path=f"/home/user/downloads/{filename}",
                        quarantine_path=f"/home/user/quarantine/{filename}",
                        filename=filename,
                        reason="Test suspicious file",
                        sha256=sha,
                    )

        except DatabaseError as e:
            raise CommandError(f"Database error while seeding data: {e}")

        except Exception as e:
            raise CommandError(f"Unexpected error while seeding data: {e}")

        self.stdout.write(self.style.SUCCESS("Done. Sample data inserted."))

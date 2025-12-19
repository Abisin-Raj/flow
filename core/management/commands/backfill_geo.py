# core/management/commands/backfill_geo.py
from django.core.management.base import BaseCommand
from django.db import close_old_connections
from core.models import Alert
from core.geolocation import lookup_ip


class Command(BaseCommand):
    help = "Backfill src_country and src_city for existing Alert rows"

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Limit number of rows to process (0 = all)",
        )

    def handle(self, *args, **options):
        limit = options.get("limit", 0)
        qs = Alert.objects.all().order_by("-id")
        if limit and limit > 0:
            qs = qs[:limit]

        count = 0
        for a in qs:
            ip = getattr(a, "src_ip", None) or None
            if not ip:
                continue
            if getattr(a, "src_country", None) and getattr(a, "src_city", None):
                continue
            geo = lookup_ip(ip)
            if not geo:
                # if private IP, mark as Local Network
                try:
                    import ipaddress
                    import socket

                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private:
                        a.src_country = a.src_country or "Local Network"
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except Exception:
                            hostname = "LAN"
                        a.src_city = a.src_city or hostname
                        a.message = (
                            a.message or ""
                        ) + f" (backfilled local: {hostname})"
                        a.save()
                        count += 1
                except Exception:
                    continue
                continue
            a.src_country = geo.get("country") or a.src_country
            a.src_city = geo.get("city") or a.src_city
            a.message = (
                (a.message or "")
                + f" (backfilled: {a.src_city or ''}{', ' if a.src_city and a.src_country else ''}{a.src_country or ''})"
            )
            a.save()
            count += 1
            if count % 50 == 0:
                close_old_connections()
        self.stdout.write(self.style.SUCCESS(f"Backfilled {count} alerts"))

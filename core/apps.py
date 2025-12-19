from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"

    def ready(self):
        # Apply sqlite pragmas in case sqlite is used
        try:
            from django.db import connection
            if connection.vendor == "sqlite":
                with connection.cursor() as cur:
                    cur.execute("PRAGMA journal_mode=WAL;")
                    cur.execute("PRAGMA synchronous=NORMAL;")
                    cur.execute("PRAGMA foreign_keys=ON;")
        except Exception:
            pass

        # Avoid running during migrations or if not root (will log warning)
        try:
            from . import firewall
            firewall.ensure_table()
            firewall.ensure_chain()
            firewall.ensure_set()
        except Exception:
            pass

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
            # Defer reconciliation to avoid DB access during app init
            # This runs 2 seconds after startup, when apps are fully loaded
            import threading
            threading.Timer(2.0, firewall.reconcile_firewall_state).start()
        except Exception:
            pass

        # Register signal handlers
        try:
            from . import signals  # noqa: F401
        except Exception:
            pass

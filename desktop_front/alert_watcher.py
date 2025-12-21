"""
Alert Watcher.

This module monitors the database for newly created alerts and triggers callbacks.
It is the "glue" that allows the desktop UI to eventually notify the user of background detections.
"""

import threading
import time
import logging
from django.db import DatabaseError, close_old_connections
from core.models import Alert

log = logging.getLogger("desktop_front.alert_watcher")


class AlertWatcher(threading.Thread):
    """
    Background thread that polls the Alert table for new entries.
    
    Attributes:
        notify_func (callable): Callback to execute when a new alert is found.
        poll_interval (int): How often (in seconds) to check DB.
        start_from_latest (bool): If True, ignore pre-existing alerts.
    """
    def __init__(self, notify_func, poll_interval=3, start_from_latest=True):
        super().__init__(daemon=True)
        self.notify = notify_func
        self.poll_interval = poll_interval
        self.last_id = None
        self.running = True
        self.start_from_latest = start_from_latest
        log.info(
            "AlertWatcher initialized with poll_interval=%s, start_from_latest=%s",
            poll_interval,
            start_from_latest,
        )

    def run(self):
        """
        Main polling loop.
        Keeps track of `last_id` to ensure each alert is notified only once.
        """
        log.info("AlertWatcher thread started")
        from django.db import connection
        while self.running:
            connection.close()
            try:
                if self.last_id is None:
                    if self.start_from_latest:
                        latest = Alert.objects.order_by("-id").first()
                        if latest:
                            self.last_id = latest.id
                            log.info(
                                "AlertWatcher: First run, starting from last_id=%s (no backfill)",
                                self.last_id,
                            )
                        else:
                            self.last_id = 0
                            log.info(
                                "AlertWatcher: No alerts in database yet, starting from 0"
                            )
                    else:
                        # Start from zero so we see all new alerts
                        self.last_id = 0
                        log.info(
                            "AlertWatcher: start_from_latest=False, starting from id 0"
                        )
                else:
                    new_alerts = Alert.objects.filter(id__gt=self.last_id).order_by("id")
                    count = new_alerts.count()

                    if count > 0:
                        log.info("AlertWatcher: Found %d new alerts", count)
                        for alert in new_alerts:
                            log.info("AlertWatcher: Notifying for alert %s", alert.id)
                            self.notify(alert)
                            self.last_id = alert.id
                    else:
                        log.debug("AlertWatcher: No new alerts")
            except DatabaseError as e:
                log.warning("AlertWatcher: Database Error: %s", e)
            except Exception as e:
                log.exception(
                    "AlertWatcher: Unexpected error in polling loop: %s", e
                )
            finally:
                close_old_connections()

            time.sleep(self.poll_interval)

        log.info("AlertWatcher thread stopped")

    def stop(self):
        log.info("AlertWatcher stop() called")
        self.running = False

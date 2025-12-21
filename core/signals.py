"""
Django signals for core app.

This module handles automatic actions triggered by model changes.
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
from core.models import Alert, BlockedIp
from core import firewall
from core.unblock_policy import should_unblock_ip
import logging

log = logging.getLogger("core.signals")


@receiver(post_save, sender=Alert)
def unblock_on_resolve(sender, instance: Alert, created, **kwargs):
    """
    Automatically unblock an IP when its associated alert is marked as resolved,
    but ONLY if no other unresolved alerts exist for that IP.
    
    This is triggered by Django's post_save signal on Alert model.
    Only runs on updates (not new alerts) when resolved=True.
    """
    # Skip newly created alerts
    if created:
        return
    
    # Only act when alert is resolved and has a source IP
    if not instance.resolved or not instance.src_ip:
        return
    
    ip = instance.src_ip
    
    # Check policy: only unblock if no other active alerts exist
    if not should_unblock_ip(ip):
        log.info(f"IP {ip} not unblocked: other active alerts exist")
        return
    
    try:
        ok, msg = firewall.unblock_ip(ip)
        if ok:
            # Clean up BlockedIp record
            BlockedIp.objects.filter(ip=ip).delete()
            log.info(f"Auto-unblocked IP {ip} after alert resolution")
        else:
            log.warning(f"Failed to auto-unblock {ip}: {msg}")
    except Exception as e:
        log.exception(f"Error in unblock_on_resolve for {ip}: {e}")


"""
ASGI config for flow project.

It exposes the ASGI callable as a module-level variable named ``application``.
This is the entry point for ASGI-compatible web servers to serve the project (e.g. for WebSockets, though not currently used).
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "flow.settings")

application = get_asgi_application()

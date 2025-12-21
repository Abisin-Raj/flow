"""
WSGI config for flow project.

It exposes the WSGI callable as a module-level variable named ``application``.
This is the entry point for WSGI-compatible web servers to serve the project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "flow.settings")

application = get_wsgi_application()

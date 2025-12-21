"""
URL configuration for flow project.

The `urlpatterns` list routes URLs to views.
Currently, this project is primarily a desktop application with a background Django ORM,
so standard web views are not heavily used, but the Admin panel is enabled.
"""

from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("admin/", admin.site.urls),

]

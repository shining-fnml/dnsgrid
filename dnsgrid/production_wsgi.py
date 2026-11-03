"""Production entry point, exclusively for the private Nginx Unix socket."""

import os

from django.core.exceptions import ImproperlyConfigured

from .proxy import UnixProxy

if not os.environ.get("DNSGRID_SECRET_KEY") or os.environ["DNSGRID_SECRET_KEY"].startswith("CHANGE"):
    raise ImproperlyConfigured("Set a persistent DNSGRID_SECRET_KEY for production.")
if os.environ.get("DNSGRID_DEBUG") == "1":
    raise ImproperlyConfigured("Web DEBUG must be disabled in production.")

from .wsgi import application as django_application

application = UnixProxy(django_application)

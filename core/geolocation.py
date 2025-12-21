"""
Geolocation Utility.

This module provides IP-to-Location mapping using a local GeoLite2 database.
It is used to enrich Alert and Connection data with country and city information.
"""

import os
import logging
import ipaddress

from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError

log = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(__file__)
# Path to the bundled GeoLite2 City database
DB_PATH = os.path.join(BASE_DIR, "..", "data", "GeoLite2-City.mmdb")

_reader = None


def _open_reader():
    """
    Lazy loader for the GeoIP2 database reader.
    Keeps the reader open for performance.
    """
    global _reader
    if _reader is None:
        if not os.path.exists(DB_PATH):
            log.error("Geo DB not found at %s", DB_PATH)
            raise FileNotFoundError(f"Geo DB not found at {DB_PATH}")
        _reader = Reader(DB_PATH)
        log.info("Opened GeoLite2 DB at %s", DB_PATH)
    return _reader


def get_geo(ip):
    """
    Lookup geographic information for an IP address.

    Args:
        ip (str): IP address to lookup.

    Returns:
        dict: containing 'country', 'city', 'latitude', 'longitude'.
              Returns special 'Local Network' values for private IPs.
              Returns None on failure or if IP is not found.
    """
    # handle obvious local addresses quickly
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return {
                "country": "Local Network",
                "city": "LAN",
                "latitude": None,
                "longitude": None,
            }
    except ValueError:
        # Not a valid IP, cannot geolocate
        return None
    except Exception:
        # Other errors, continue to try lookup (though unlikely to succeed if ipaddress failed)
        pass

    try:
        reader = _open_reader()
    except Exception as e:
        log.exception("Failed opening Geo DB: %s", e)
        return None

    try:
        r = reader.city(ip)
        return {
            "country": getattr(r.country, "name", None),
            "city": getattr(r.city, "name", None),
            "latitude": getattr(r.location, "latitude", None),
            "longitude": getattr(r.location, "longitude", None),
        }
    except AddressNotFoundError:
        # IP not in DB, treat as unknown external
        log.debug("Geo lookup: address not in database for %s", ip)
        return None
    except Exception as e:
        log.exception("Geo lookup failed for %s: %s", ip, e)
        return None


def close_reader():
    """
    Explicitly close the GeoIP2 reader and release the file handle.
    """
    global _reader
    if _reader is not None:
        try:
            _reader.close()
            log.info("Closed GeoLite2 DB reader")
        except Exception:
            log.exception("Failed to close Geo reader")
        finally:
            _reader = None

# File: core/geolocation.py
import os
import logging
import ipaddress

from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError

log = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "..", "data", "GeoLite2-City.mmdb")

_reader = None


def _open_reader():
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
    Return a dict with keys: country, city, latitude, longitude.
    Return None on failure or for private/local addresses.
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
    global _reader
    if _reader is not None:
        try:
            _reader.close()
            log.info("Closed GeoLite2 DB reader")
        except Exception:
            log.exception("Failed to close Geo reader")
        finally:
            _reader = None

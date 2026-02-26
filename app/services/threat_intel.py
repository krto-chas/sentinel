import os
import requests
import geoip2.database
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient, InsertOne, ASCENDING
from pymongo.errors import BulkWriteError
from typing import List, Dict, Optional, Set
from hashlib import sha256
import ipaddress
import socket
from urllib.parse import urlparse

# --- Konfiguration ---
MONGO_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGODB_DB_NAME", "sentinel")
FEODO_TRACKER_URL = os.getenv("FEODO_TRACKER_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.json")
URLHAUS_RECENT_URL = os.getenv("URLHAUS_RECENT_URL", "https://urlhaus.abuse.ch/downloads/json_recent/")
THREATFOX_API_URL = os.getenv("THREATFOX_API_URL", "https://threatfox-api.abuse.ch/api/v1/")
THREATFOX_API_KEY_FILE = os.getenv("THREATFOX_API_KEY_FILE", "")
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "/app/assets/GeoLite2-City.mmdb")
THREAT_LOOKBACK_DAYS = int(os.getenv("THREAT_LOOKBACK_DAYS", "90"))
URLHAUS_MAX_ITEMS = int(os.getenv("URLHAUS_MAX_ITEMS", "1000"))
THREATFOX_MAX_ITEMS = int(os.getenv("THREATFOX_MAX_ITEMS", "200"))
THREATFOX_DAYS = max(1, min(7, int(os.getenv("THREATFOX_DAYS", "7"))))
THREAT_RESOLVE_DOMAINS = os.getenv("THREAT_RESOLVE_DOMAINS", "false").lower() in {"1", "true", "yes", "on"}
THREAT_INTEL_MIN_CONFIDENCE = int(os.getenv("THREAT_INTEL_MIN_CONFIDENCE", "70"))
THREAT_INTEL_MAX_EVENTS_PER_RUN = int(os.getenv("THREAT_INTEL_MAX_EVENTS_PER_RUN", "500"))
THREAT_INTEL_ALLOWED_SOURCES = os.getenv("THREAT_INTEL_ALLOWED_SOURCES", "Feodo Tracker,URLhaus,ThreatFox")


def _parse_allowed_sources(raw: str) -> Set[str]:
    values = [item.strip() for item in raw.split(",")]
    return {item for item in values if item}


def _load_secret_env_value(name: str, file_path: str) -> str:
    direct_value = os.getenv(name, "")
    if direct_value:
        return direct_value
    if not file_path:
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


THREATFOX_API_KEY = _load_secret_env_value("THREATFOX_API_KEY", THREATFOX_API_KEY_FILE)
ALLOWED_THREAT_SOURCES = _parse_allowed_sources(THREAT_INTEL_ALLOWED_SOURCES)

# Fix för lokal utveckling: Om Docker-sökvägen inte finns, leta i lokal assets-mapp
if not os.path.exists(GEOIP_DB_PATH):
    # Försök hitta den relativt till projektets rot (där man oftast kör uvicorn)
    local_path = os.path.join(os.getcwd(), "assets", "GeoLite2-City.mmdb")
    if os.path.exists(local_path):
        GEOIP_DB_PATH = local_path

# --- Databasanslutning ---
client: MongoClient = MongoClient(MONGO_URI)
db = client[MONGO_DB_NAME]
threat_events_collection = db["threat_events"]

def get_geolocation(ip_address: str) -> Optional[Dict]:
    """Translates an IP address to geolocation data (lat/lon)."""
    if not os.path.exists(GEOIP_DB_PATH):
        # Print only once per batch or handle logging better to avoid spam, but for now:
        return None
        
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip_address)
            return {
                "lat": response.location.latitude,
                "lon": response.location.longitude,
                "city": response.city.name,
                "country": response.country.iso_code,
            }
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None
    except Exception as e:
        print(f"Error during GeoIP lookup for {ip_address}: {e}")
        return None


def _ip_from_host(host: str) -> Optional[str]:
    if not host:
        return None
    host = host.strip().lower()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # Safety default: avoid DNS lookups to suspicious IOC domains unless explicitly enabled.
    if not THREAT_RESOLVE_DOMAINS:
        return None

    try:
        resolved = socket.gethostbyname(host)
        ip = ipaddress.ip_address(resolved)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return None
        return resolved
    except Exception:
        return None


def _make_event(
    source: str,
    timestamp: datetime,
    lat: float,
    lon: float,
    severity: str,
    event_type: str,
    ioc: str,
    confidence: int,
    details: Dict,
) -> Dict:
    event = {
        "source": source,
        "timestamp": timestamp,
        "event_day": timestamp.date().isoformat(),
        "lat": lat,
        "lon": lon,
        "severity": severity,
        "type": event_type,
        "ioc": ioc,
        "confidence": confidence,
        "details": details,
    }
    fingerprint = f"{event['source']}|{event['ioc']}|{event['event_day']}"
    event["event_fingerprint"] = sha256(fingerprint.encode("utf-8")).hexdigest()
    return event

def fetch_and_normalize_feodo_iocs() -> List[Dict]:
    """Fetches Feodo Tracker data and normalizes it."""
    print("Fetching threat intelligence from Feodo Tracker...")
    try:
        response = requests.get(FEODO_TRACKER_URL, headers={"User-Agent": "SentinelUploadAPI/1.0"}, timeout=10)
        response.raise_for_status()
        iocs = response.json()
    except Exception as e:
        print(f"Failed to fetch Feodo data: {e}")
        return []

    normalized_events = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=THREAT_LOOKBACK_DAYS)

    def parse_feodo_dt(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        candidates = (
            "%Y-%m-%d %H:%M:%S %Z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        )
        for fmt in candidates:
            try:
                dt = datetime.strptime(value, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    for ioc in iocs:
        ip_address = ioc.get("ip_address")
        if not ip_address:
            continue

        # Feodo often has few/no "online" entries; use recency filter instead.
        last_online = parse_feodo_dt(ioc.get("last_online"))
        if last_online and last_online < cutoff:
            continue

        geo_data = get_geolocation(ip_address)
        if not geo_data:
            continue

        # Parse first_seen using known Feodo fields/formats.
        first_seen = (
            parse_feodo_dt(ioc.get("first_seen"))
            or parse_feodo_dt(ioc.get("first_seen_utc"))
            or datetime.now(timezone.utc)
        )

        event = _make_event(
            source="Feodo Tracker",
            timestamp=first_seen,
            lat=geo_data["lat"],
            lon=geo_data["lon"],
            severity="high",
            event_type="C2",
            ioc=ip_address,
            confidence=100,
            details={
                "malware_family": ioc.get("malware"),
                "country": ioc.get("country"),
                "city": geo_data.get("city"),
                "status": ioc.get("status"),
                "last_online": ioc.get("last_online"),
            },
        )
        normalized_events.append(event)
    
    print(f"Normalized {len(normalized_events)} events from Feodo Tracker using DB at {GEOIP_DB_PATH}.")
    return normalized_events


def fetch_and_normalize_urlhaus_iocs() -> List[Dict]:
    """Fetches URLhaus recent feed and normalizes entries with resolvable host geodata."""
    print("Fetching threat intelligence from URLhaus...")
    try:
        response = requests.get(URLHAUS_RECENT_URL, headers={"User-Agent": "SentinelUploadAPI/1.0"}, timeout=12)
        response.raise_for_status()
        body = response.json()
        rows: List[Dict]
        if isinstance(body, list):
            rows = body
        elif isinstance(body, dict):
            # URLhaus variants:
            # - {"urls":[...]}
            # - {"query_status":"ok","urls":[...]}
            # - {"<id>": {...}, "<id>": {...}} (ID-keyed dict)
            candidate_rows = body.get("urls")
            if isinstance(candidate_rows, list):
                rows = candidate_rows
            else:
                id_keyed: List[Dict] = []
                for value in body.values():
                    if isinstance(value, dict):
                        id_keyed.append(value)
                    elif isinstance(value, list):
                        id_keyed.extend([row for row in value if isinstance(row, dict)])
                if id_keyed:
                    rows = id_keyed
                else:
                    print(f"URLhaus feed returned unexpected dict shape: keys={list(body.keys())[:8]}")
                    return []
        else:
            print(f"URLhaus feed returned unsupported shape: {type(body).__name__}")
            return []
    except Exception as e:
        print(f"Failed to fetch URLhaus data: {e}")
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=THREAT_LOOKBACK_DAYS)
    normalized_events = []

    for row in rows[:URLHAUS_MAX_ITEMS]:
        host = (row.get("host") or "").strip().lower()
        if not host:
            parsed = urlparse(row.get("url", ""))
            host = (parsed.hostname or "").strip().lower()
        ip_address = _ip_from_host(host)
        if not ip_address:
            continue

        geo_data = get_geolocation(ip_address)
        if not geo_data:
            continue

        raw_date = row.get("dateadded") or row.get("date_added")
        timestamp = datetime.now(timezone.utc)
        if raw_date:
            try:
                timestamp = datetime.strptime(raw_date, "%Y-%m-%d %H:%M:%S %Z").replace(tzinfo=timezone.utc)
            except ValueError:
                try:
                    timestamp = datetime.strptime(raw_date, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
        if timestamp < cutoff:
            continue

        event = _make_event(
            source="URLhaus",
            timestamp=timestamp,
            lat=geo_data["lat"],
            lon=geo_data["lon"],
            severity="medium",
            event_type="Malware URL",
            ioc=row.get("url") or ip_address,
            confidence=80,
            details={
                "country": geo_data.get("country"),
                "city": geo_data.get("city"),
                "host": host,
                "ip": ip_address,
                "url_status": row.get("url_status"),
                "threat": row.get("threat"),
                "tags": row.get("tags"),
            },
        )
        normalized_events.append(event)

    print(f"Normalized {len(normalized_events)} events from URLhaus.")
    return normalized_events


def fetch_and_normalize_threatfox_iocs() -> List[Dict]:
    """Fetches ThreatFox IOC feed and normalizes rows with geolocation."""
    print("Fetching threat intelligence from ThreatFox...")
    headers = {"User-Agent": "SentinelUploadAPI/1.0", "Content-Type": "application/json"}
    if THREATFOX_API_KEY:
        headers["Auth-Key"] = THREATFOX_API_KEY

    # ThreatFox API for get_iocs accepts days in [1..7].
    payload = {"query": "get_iocs", "days": THREATFOX_DAYS}
    try:
        response = requests.post(THREATFOX_API_URL, json=payload, headers=headers, timeout=12)
        response.raise_for_status()
        body = response.json()
        if not isinstance(body, dict):
            print(f"ThreatFox feed returned unsupported shape: {type(body).__name__}")
            return []
        status = body.get("query_status")
        if status not in {"ok", "no_result"}:
            print(f"ThreatFox query status: {status}")
        rows = body.get("data", [])
        if status == "no_result":
            return []
        if not isinstance(rows, list):
            print(f"ThreatFox feed returned unexpected data shape: {type(rows).__name__}")
            return []
    except Exception as e:
        print(f"Failed to fetch ThreatFox data: {e}")
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=THREAT_LOOKBACK_DAYS)
    normalized_events: List[Dict] = []

    def parse_ts(value: Optional[str]) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return datetime.now(timezone.utc)

    for row in rows[:THREATFOX_MAX_ITEMS]:
        ioc_value = (row.get("ioc") or "").strip()
        if not ioc_value:
            continue

        ioc_type = (row.get("ioc_type") or "").lower()
        ip_address: Optional[str] = None
        if ioc_type in {"ip:port", "ip"}:
            ip_address = ioc_value.split(":")[0]
        elif ioc_type in {"domain", "hostname"}:
            ip_address = _ip_from_host(ioc_value)
        elif ioc_type == "url":
            parsed = urlparse(ioc_value)
            ip_address = _ip_from_host(parsed.hostname or "")

        if not ip_address:
            continue

        geo_data = get_geolocation(ip_address)
        if not geo_data:
            continue

        timestamp = parse_ts(row.get("first_seen") or row.get("last_seen"))
        if timestamp < cutoff:
            continue

        event = _make_event(
            source="ThreatFox",
            timestamp=timestamp,
            lat=geo_data["lat"],
            lon=geo_data["lon"],
            severity="high",
            event_type=row.get("threat_type") or "IOC",
            ioc=ioc_value,
            confidence=int(row.get("confidence_level") or 70),
            details={
                "country": geo_data.get("country"),
                "city": geo_data.get("city"),
                "ioc_type": row.get("ioc_type"),
                "malware_family": row.get("malware"),
                "reporter": row.get("reporter"),
                "tags": row.get("tags"),
            },
        )
        normalized_events.append(event)

    print(f"Normalized {len(normalized_events)} events from ThreatFox.")
    return normalized_events

def setup_database_indexes():
    """Creates necessary indexes."""
    # TTL index: delete after 7 days (604800 seconds)
    threat_events_collection.create_index([("timestamp", ASCENDING)], expireAfterSeconds=604800)
    # Migrate away from the older strict unique index if it exists.
    try:
        threat_events_collection.drop_index("ioc_1_source_1")
    except Exception:
        pass
    # Unique per IOC/source/day to allow temporal variation while avoiding spam duplicates.
    threat_events_collection.create_index([("event_fingerprint", ASCENDING)], unique=True)
    print("Threat intelligence indexes setup complete.")

def save_events_to_db(events: List[Dict]):
    """Saves events to DB, ignoring duplicates."""
    if not events:
        return

    filtered = [
        event
        for event in events
        if int(event.get("confidence", 0)) >= THREAT_INTEL_MIN_CONFIDENCE
    ]
    limited = filtered[:THREAT_INTEL_MAX_EVENTS_PER_RUN]

    if not limited:
        print("No events matched current threat-intel policy filters.")
        return

    operations = [InsertOne(event) for event in limited]
    try:
        result = threat_events_collection.bulk_write(operations, ordered=False)
        print(f"Inserted {result.inserted_count} new threat events.")
    except BulkWriteError as bwe:
        print(f"Inserted {bwe.details['nInserted']} new events (duplicates skipped).")
    except Exception as e:
        print(f"Database write error: {e}")

def run_threat_intel_update_job():
    """Main job function."""
    print("Running threat intelligence update job...")
    events: List[Dict] = []
    if "Feodo Tracker" in ALLOWED_THREAT_SOURCES:
        events.extend(fetch_and_normalize_feodo_iocs())
    if "URLhaus" in ALLOWED_THREAT_SOURCES:
        events.extend(fetch_and_normalize_urlhaus_iocs())
    if "ThreatFox" in ALLOWED_THREAT_SOURCES:
        events.extend(fetch_and_normalize_threatfox_iocs())
    save_events_to_db(events)

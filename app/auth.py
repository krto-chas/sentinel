"""
auth.py – API-nyckelbaserad autentisering för Sentinel Upload API.

Stöder tre lägen via miljövariabeln AUTH_MODE:
  off      – Ingen autentisering (default, bakåtkompatibelt)
  apikey   – Enkel API-nyckel i X-API-Key-headern
  firebase – Firebase ID-token i Authorization: Bearer-headern

API-nycklar lagras som kommaseparerad lista i SENTINEL_API_KEYS.
Varje nyckel kan ha ett prefix för att identifiera ägare: "user1:abc123,user2:xyz456"
Om inget prefix anges används "anonymous" som user_id.
"""

import logging
import os
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger("sentinel.auth")

AUTH_MODE = os.getenv("AUTH_MODE", "off").lower()

# Bygg upp en dict med nyckel -> user_id från SENTINEL_API_KEYS
# Format: "userid1:key1,userid2:key2" eller bara "key1,key2"
_raw_keys = os.getenv("SENTINEL_API_KEYS", "")
_API_KEY_MAP: dict[str, str] = {}

for entry in _raw_keys.split(","):
    entry = entry.strip()
    if not entry:
        continue
    if ":" in entry:
        uid, key = entry.split(":", 1)
        _API_KEY_MAP[key.strip()] = uid.strip()
    else:
        _API_KEY_MAP[entry] = "anonymous"

_bearer_scheme = HTTPBearer(auto_error=False)


def _resolve_apikey_user(request: Request) -> str | None:
    """Försök att lösa ut user_id från X-API-Key-headern."""
    key = request.headers.get("X-API-Key", "").strip()
    if not key:
        return None
    return _API_KEY_MAP.get(key)


async def _resolve_firebase_user(
    credentials: HTTPAuthorizationCredentials | None,
) -> str | None:
    """Löser ut user_id från ett Firebase ID-token (Bearer)."""
    if credentials is None or not credentials.credentials:
        return None
    token = credentials.credentials
    try:
        import firebase_admin
        from firebase_admin import auth as fb_auth

        # Initialisera Firebase-appen om den inte redan är initialiserad.
        # Använder get_app() (publik API) istället för det privata _apps-attributet.
        try:
            firebase_admin.get_app()
        except ValueError:
            creds_file = os.getenv("FIREBASE_CREDENTIALS_FILE")
            creds_json = os.getenv("FIREBASE_CREDENTIALS_JSON")
            if creds_file:
                from firebase_admin import credentials as fb_creds
                firebase_admin.initialize_app(fb_creds.Certificate(creds_file))
            elif creds_json:
                import json
                from firebase_admin import credentials as fb_creds
                firebase_admin.initialize_app(
                    fb_creds.Certificate(json.loads(creds_json))
                )
            else:
                firebase_admin.initialize_app()

        decoded = fb_auth.verify_id_token(token)
        return decoded.get("uid") or decoded.get("email") or "firebase-user"
    except Exception as exc:
        logger.warning("Firebase token verification failed: %s", exc)
        return None


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> str:
    """
    FastAPI-dependency som returnerar user_id för den autentiserade användaren.

    Om AUTH_MODE=off returneras alltid "anonymous".
    Vid fel kastas HTTP 401.
    """
    if AUTH_MODE == "off":
        return "anonymous"

    if AUTH_MODE == "apikey":
        user_id = _resolve_apikey_user(request)
        if user_id is None:
            logger.warning(
                "Unauthorized upload attempt from %s – ogiltig eller saknad API-nyckel",
                request.client.host if request.client else "unknown",
            )
            raise HTTPException(
                status_code=401,
                detail="Ogiltig eller saknad API-nyckel. Ange X-API-Key-header.",
            )
        return user_id

    if AUTH_MODE == "firebase":
        user_id = await _resolve_firebase_user(credentials)
        if user_id is None:
            raise HTTPException(
                status_code=401,
                detail="Ogiltig eller saknad Firebase-token.",
            )
        return user_id

    # Okänt läge – fail-closed
    raise HTTPException(status_code=500, detail=f"Okänt AUTH_MODE: {AUTH_MODE}")
import json
import os
from functools import lru_cache

import firebase_admin
from fastapi import Header, HTTPException
from firebase_admin import auth, credentials


def auth_mode() -> str:
    return os.getenv("AUTH_MODE", "off").strip().lower()


@lru_cache
def _firebase_app():
    creds_json = os.getenv("FIREBASE_CREDENTIALS_JSON", "").strip()
    creds_file = os.getenv("FIREBASE_CREDENTIALS_FILE", "").strip()

    cred = None
    if creds_json:
        cred = credentials.Certificate(json.loads(creds_json))
    elif creds_file:
        cred = credentials.Certificate(creds_file)

    try:
        if cred is not None:
            return firebase_admin.initialize_app(cred)
        return firebase_admin.initialize_app()
    except ValueError:
        return firebase_admin.get_app()


def require_auth(authorization: str | None = Header(default=None)):
    mode = auth_mode()
    if mode != "firebase":
        return {"uid": "anonymous"}

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    try:
        app = _firebase_app()
        decoded = auth.verify_id_token(token, app=app)
        return decoded
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

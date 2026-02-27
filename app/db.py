from functools import lru_cache
import os

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConfigurationError


@lru_cache
def _mongo_uri() -> str:
    return os.getenv("MONGODB_URI", "mongodb://localhost:27017/sentinel_upload")


@lru_cache
def get_mongo_client() -> AsyncIOMotorClient:
    # Singleton – Motor manages its own connection pool internally.
    return AsyncIOMotorClient(_mongo_uri())


def get_db():
    client = get_mongo_client()
    try:
        # Preferred: database name in URI path (e.g. ...mongodb.net/sentinel_upload)
        return client.get_default_database()
    except ConfigurationError:
        # Fallback for URIs without db path.
        return client.get_database(os.getenv("MONGO_DB", "sentinel_upload"))


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except ValueError:
        return default


async def ensure_upload_indexes():
    """
    Ensure indexes needed for query performance and automatic retention.
    """
    db = get_db()
    retention_days = _env_int("UPLOAD_RETENTION_DAYS", 30)
    await db.uploads.create_index("sha256")
    await db.uploads.create_index(
        "created_at",
        expireAfterSeconds=retention_days * 24 * 60 * 60,
        name="uploads_created_at_ttl",
    )

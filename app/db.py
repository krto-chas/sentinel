from functools import lru_cache
import os

from motor.motor_asyncio import AsyncIOMotorClient


@lru_cache
def _mongo_uri() -> str:
    return os.getenv("MONGODB_URI", "mongodb://localhost:27017/sentinel_upload")


def get_mongo_client() -> AsyncIOMotorClient:
    # Lazy client creation; connect on first use.
    return AsyncIOMotorClient(_mongo_uri())


def get_db():
    # Database name comes from the URI path.
    return get_mongo_client().get_default_database()

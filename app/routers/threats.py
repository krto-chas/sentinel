from fastapi import APIRouter, Query
from typing import List, Dict, Any
from pymongo import DESCENDING
from app.services.threat_intel import threat_events_collection

router = APIRouter(
    prefix="/api/v1/threats",
    tags=["Threat Intelligence"],
)

@router.get(
    "/",
    response_model=List[Dict[str, Any]],
    summary="Get latest threat intelligence events"
)
async def get_latest_threats(limit: int = Query(100, ge=1, le=1000)):
    """
    Returns the most recent threat events with geolocation data.
    """
    events_cursor = threat_events_collection.find({}, {"_id": 0}).sort("timestamp", DESCENDING).limit(limit)
    return list(events_cursor)
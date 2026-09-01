"""Crowd-sourced threat reporting — "Report as Scam"."""
from fastapi import APIRouter
from pydantic import BaseModel

from services import storage

router = APIRouter(prefix="/api", tags=["report"])


class ReportRequest(BaseModel):
    url: str | None = None
    message_snippet: str = ""
    category: str = "Other"
    language: str = "en"


@router.post("/report")
def report_scam(req: ReportRequest):
    if not req.url and not req.message_snippet:
        return {"status": "error", "reason": "Provide a URL or a message snippet to report."}
    result = storage.add_report(req.url, req.message_snippet, req.category, req.language)
    return {"status": "recorded", **result}


@router.get("/reports")
def list_reports(limit: int = 50):
    return {"reports": storage.get_reports(limit)}

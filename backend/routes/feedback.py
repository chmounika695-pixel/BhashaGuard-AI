"""Human-in-the-loop feedback — "Was this detection correct?" """
from fastapi import APIRouter
from pydantic import BaseModel

from services import storage

router = APIRouter(prefix="/api", tags=["feedback"])


class FeedbackRequest(BaseModel):
    analysis_id: str
    correct: bool
    feedback_type: str | None = None  # false_positive/false_negative/wrong_language/wrong_category/other


@router.post("/feedback")
def submit_feedback(req: FeedbackRequest):
    entry = storage.add_feedback(req.analysis_id, req.correct, req.feedback_type)
    return {"status": "recorded", "feedback_id": entry["id"]}

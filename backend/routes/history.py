"""Detection history and threat-insights dashboard data — both computed
from real stored data, never invented statistics."""
import json
import os

from fastapi import APIRouter

from services import storage

router = APIRouter(prefix="/api", tags=["history"])

_EVAL_RESULTS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "eval_results.json")


@router.get("/history")
def get_history(limit: int = 50):
    return {"history": storage.get_history(limit)}


@router.get("/insights")
def get_insights():
    return storage.get_insights()


@router.get("/eval")
def get_eval_results():
    if not os.path.exists(_EVAL_RESULTS_PATH):
        return {"available": False, "reason": "Run scripts/evaluate.py on the backend to generate this."}
    with open(_EVAL_RESULTS_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return {"available": True, **data}

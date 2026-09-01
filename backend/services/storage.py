"""
Lightweight persistence for detection history, user feedback, and
community-reported scams.

Honest scope note: this uses local JSON files, not Supabase/PostgreSQL.
The Phase-I proposal named Supabase; committing to real hosted Postgres
setup, credentials, and migrations was not realistic within this
timeline without either breaking under demo conditions or being faked.
This keeps the *interface* (functions below) identical to what a
Postgres-backed version would expose, so swapping the storage backend
later is a implementation swap, not a redesign — noted in the README
roadmap.

Privacy: history entries store only a truncated snippet of the original
text (first 80 chars), never the full message, and never raw screenshot
image bytes — matching the project's stated privacy principles.
"""
import json
import os
import time
import uuid
from threading import Lock

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(_DATA_DIR, exist_ok=True)

_HISTORY_FILE = os.path.join(_DATA_DIR, "history.json")
_FEEDBACK_FILE = os.path.join(_DATA_DIR, "feedback.json")
_REPORTS_FILE = os.path.join(_DATA_DIR, "reports.json")

_lock = Lock()


def _load(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save(path: str, data: list) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _truncate(text: str, max_len: int = 80) -> str:
    text = text.strip()
    return text if len(text) <= max_len else text[:max_len] + "…"


def add_history_entry(input_type: str, text: str, language: dict, verdict: dict) -> dict:
    with _lock:
        history = _load(_HISTORY_FILE)
        entry = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": time.time(),
            "input_type": input_type,
            "text_snippet": _truncate(text),
            "language": language.get("language_name", "Unknown"),
            "category": verdict.get("category", "Other"),
            "risk_score": verdict.get("final_risk_score", 0),
            "tier": verdict.get("tier", "SAFE"),
        }
        history.insert(0, entry)
        history = history[:500]  # cap growth for a demo deployment
        _save(_HISTORY_FILE, history)
        return entry


def get_history(limit: int = 50) -> list:
    return _load(_HISTORY_FILE)[:limit]


def add_feedback(analysis_id: str, correct: bool, feedback_type: str | None) -> dict:
    with _lock:
        feedback = _load(_FEEDBACK_FILE)
        entry = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": time.time(),
            "analysis_id": analysis_id,
            "correct": correct,
            "feedback_type": feedback_type,  # false_positive/false_negative/wrong_language/wrong_category/other
        }
        feedback.append(entry)
        _save(_FEEDBACK_FILE, feedback)
        return entry


def add_report(url: str | None, message_snippet: str, category: str, language: str) -> dict:
    """Community threat report. Reputation is a simple report-count
    threshold — a single report never marks something malicious."""
    with _lock:
        reports = _load(_REPORTS_FILE)
        key = (url or message_snippet).strip().lower()
        entry = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": time.time(),
            "key": key,
            "url": url,
            "message_snippet": _truncate(message_snippet),
            "category": category,
            "language": language,
        }
        reports.append(entry)
        _save(_REPORTS_FILE, reports)

        count = sum(1 for r in reports if r["key"] == key)
        if count >= 5:
            reputation = "High Risk"
        elif count >= 2:
            reputation = "Suspicious"
        else:
            reputation = "Unverified (single report)"
        return {"report_id": entry["id"], "total_reports_for_this_item": count, "reputation": reputation}


def get_reports(limit: int = 50) -> list:
    return _load(_REPORTS_FILE)[-limit:][::-1]


def get_insights() -> dict:
    """Real aggregate stats computed from stored history — never invented."""
    history = _load(_HISTORY_FILE)
    reports = _load(_REPORTS_FILE)

    total = len(history)
    by_tier = {}
    by_language = {}
    by_category = {}
    for entry in history:
        by_tier[entry["tier"]] = by_tier.get(entry["tier"], 0) + 1
        by_language[entry["language"]] = by_language.get(entry["language"], 0) + 1
        by_category[entry["category"]] = by_category.get(entry["category"], 0) + 1

    threats_detected = sum(v for k, v in by_tier.items() if k != "SAFE")
    high_risk = by_tier.get("HIGH RISK", 0) + by_tier.get("PHISHING", 0)

    return {
        "total_analyses": total,
        "threats_detected": threats_detected,
        "high_risk_detections": high_risk,
        "community_reports": len(reports),
        "by_tier": by_tier,
        "by_language": by_language,
        "by_category": by_category,
    }

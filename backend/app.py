"""
BhashaGuard AI — backend.

Composed of route modules under routes/ (scan, feedback, report, history)
rather than one monolithic file — each is independently testable and maps
to one feature area. services/pipeline.py is the single shared analysis
pipeline every route (text, screenshot, QR) runs through.

Run locally:
    pip install -r requirements.txt
    export GROQ_API_KEY=your_key_here   # optional — falls back to a
                                         # deterministic rule-based scorer
    uvicorn app:app --reload --port 8000

Then open http://localhost:8000 — the dashboard UI is served from the
same origin as the API (frontend/index.html), and interactive API docs
are at http://localhost:8000/docs (FastAPI auto-generates these).
"""
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from services.pipeline import run_pipeline
from services.voice import generate_voice_base64
from routes import scan, feedback, report, history

app = FastAPI(
    title="BhashaGuard AI",
    version="0.2.0",
    description="Multilingual, code-mixed phishing detection for regional-language users.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # fine for a hackathon demo; lock down in production
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(feedback.router)
app.include_router(report.router)
app.include_router(history.router)


@app.get("/api/health")
def health():
    from services import ocr_service, qr_service
    return {
        "status": "ok",
        "service": "BhashaGuard AI",
        "ocr_available": ocr_service.is_available(),
        "qr_available": qr_service.is_available(),
        "llm_configured": bool(os.getenv("GROQ_API_KEY")),
    }


# --- Legacy endpoints, kept for backward compatibility -----------------
# The original MVP exposed /analyze and /analyze/voice directly. New
# clients should use /api/scan (routes/scan.py), which supersedes both —
# these now just delegate to the same pipeline.

class AnalyzeRequest(BaseModel):
    text: str


@app.post("/analyze")
def analyze_legacy(req: AnalyzeRequest):
    result = run_pipeline(req.text, input_type="text")
    return {
        "input_text": result["input_text"],
        "language": result["language"],
        "content_analysis": result["content_analysis"],
        "url_analysis": result["url_analysis"],
        "verdict": result["verdict"],
    }


@app.post("/analyze/voice")
def analyze_voice_legacy(req: AnalyzeRequest):
    result = run_pipeline(req.text, input_type="text")
    audio_b64 = generate_voice_base64(result["verdict"]["explanation_native"], result["language"]["language_code"])
    return {
        "language": result["language"],
        "verdict": result["verdict"],
        "audio_base64_mp3": audio_b64,
    }


# Serve the dashboard UI from the same origin as the API — one deployment
# link covers both. Mounted last so explicit routes above always win.
_frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(_frontend_dir):
    app.mount("/", StaticFiles(directory=_frontend_dir, html=True), name="frontend")

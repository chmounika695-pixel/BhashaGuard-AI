"""
Screenshot OCR — extracts text from uploaded scam screenshots (WhatsApp
messages, fake payment receipts) so it can be run through the same
language detection + content risk pipeline as typed text.

Primary path: Groq's vision-capable LLM. This needs no system-level
install at all beyond the GROQ_API_KEY you already configure for the
content-risk LLM refinement layer — no Tesseract binary, no separate
setup step, which matters a lot given how fragile system-binary
installs proved to be on Windows/Python 3.14 during this project. It
also reads regional-script text (Hindi/Tamil/etc.) more reliably than
Tesseract's default English-trained model.

Fallback path: pytesseract, if a GROQ_API_KEY isn't configured and the
system Tesseract binary happens to be installed. Both paths are real
code, not placeholders — but if neither is available, `is_available()`
reports that honestly rather than pretending OCR ran.

Note: the Groq vision call could not be tested live from the build
sandbox (no network route to api.groq.com there) — the request follows
Groq's documented OpenAI-compatible vision format. If GROQ_VISION_MODEL
needs adjusting for whatever model id is live on your account, set it
via the environment variable of the same name.

Install (optional, fallback path only):
    pip install pytesseract Pillow
    # + system Tesseract binary:
    #   Windows: https://github.com/UB-Mannheim/tesseract/wiki
    #   Mac:     brew install tesseract
    #   Linux:   apt install tesseract-ocr
"""
import base64
import io
import os

MAX_IMAGE_BYTES = 3 * 1024 * 1024  # leaves headroom for base64 expansion under Groq's 4 MB encoded-image limit

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_VISION_MODEL = os.getenv("GROQ_VISION_MODEL", "qwen/qwen3.6-27b")

try:
    import pytesseract
    from PIL import Image
    _TESSERACT_IMPORTS_OK = True
except ImportError:
    _TESSERACT_IMPORTS_OK = False


def _tesseract_available() -> bool:
    if not _TESSERACT_IMPORTS_OK:
        return False
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def is_available() -> bool:
    return bool(GROQ_API_KEY) or _tesseract_available()


def _image_mime_type(image_bytes: bytes) -> str:
    """Best-effort MIME detection without trusting the browser filename."""
    try:
        from PIL import Image
        with Image.open(io.BytesIO(image_bytes)) as image:
            fmt = (image.format or "PNG").upper()
        return {
            "JPEG": "image/jpeg",
            "JPG": "image/jpeg",
            "PNG": "image/png",
            "WEBP": "image/webp",
            "GIF": "image/gif",
        }.get(fmt, "image/png")
    except Exception:
        return "image/png"


def _extract_via_groq_vision(image_bytes: bytes) -> str:
    from groq import Groq

    b64 = base64.b64encode(image_bytes).decode("utf-8")
    mime = _image_mime_type(image_bytes)
    client = Groq(api_key=GROQ_API_KEY)
    completion = client.chat.completions.create(
        model=GROQ_VISION_MODEL,
        messages=[{
            "role": "user",
            "content": [
                {"type": "text", "text": (
                    "Transcribe ALL readable text in this image exactly as it appears, "
                    "including any regional Indian language text (Hindi/Tamil/Telugu/"
                    "Bengali/Kannada), in its original script. Output only the "
                    "transcribed text, nothing else — no commentary."
                )},
                {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}},
            ],
        }],
        temperature=0,
        max_tokens=600,
    )
    return completion.choices[0].message.content.strip()


def _extract_via_tesseract(image_bytes: bytes) -> str:
    image = Image.open(io.BytesIO(image_bytes))
    return pytesseract.image_to_string(image).strip()


def extract_text(image_bytes: bytes) -> dict:
    if not image_bytes:
        return {
            "available": False,
            "text": "",
            "reason": "The uploaded image is empty. Please choose a valid screenshot.",
            "engine": None,
        }

    if len(image_bytes) > MAX_IMAGE_BYTES:
        return {
            "available": False,
            "text": "",
            "reason": "The screenshot is larger than 3 MB. Please compress or resize it and try again.",
            "engine": None,
        }

    if GROQ_API_KEY:
        try:
            text = _extract_via_groq_vision(image_bytes)
            return {"available": True, "text": text, "reason": None, "engine": f"groq_vision:{GROQ_VISION_MODEL}"}
        except Exception as exc:
            # Fall through to Tesseract rather than failing outright.
            groq_error = f"{exc.__class__.__name__}: {exc}"
            if _tesseract_available():
                try:
                    text = _extract_via_tesseract(image_bytes)
                    return {"available": True, "text": text, "reason": f"(Groq vision failed: {groq_error}; used Tesseract instead)", "engine": "tesseract"}
                except Exception as exc2:
                    return {"available": False, "text": "", "reason": f"Groq vision failed ({groq_error}) and Tesseract failed ({exc2}).", "engine": None}
            return {"available": False, "text": "", "reason": f"Groq vision failed: {groq_error}. No local Tesseract fallback installed.", "engine": None}

    if _tesseract_available():
        try:
            text = _extract_via_tesseract(image_bytes)
            return {"available": True, "text": text, "reason": None, "engine": "tesseract"}
        except Exception as exc:
            return {"available": False, "text": "", "reason": f"OCR failed: {exc.__class__.__name__}: {exc}", "engine": None}

    return {
        "available": False,
        "text": "",
        "reason": "OCR not available — set GROQ_API_KEY (recommended, no extra install needed), or install pytesseract + the system Tesseract binary.",
        "engine": None,
    }

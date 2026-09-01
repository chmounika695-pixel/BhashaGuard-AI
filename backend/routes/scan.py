"""
Scan routes — the core detection surface. All three input modes (typed
text/URL, screenshot upload, QR image upload) funnel into the same
`run_pipeline()` so scoring logic is never duplicated per input type.
"""
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pydantic import BaseModel

from services.pipeline import run_pipeline
from services.voice import generate_voice_base64
from services import ocr_service, qr_service

router = APIRouter(prefix="/api", tags=["scan"])


class ScanRequest(BaseModel):
    text: str
    warning_language: str | None = None
    include_voice: bool = True


@router.post("/scan")
def scan(req: ScanRequest):
    result = run_pipeline(req.text, warning_language=req.warning_language, input_type="text")
    if req.include_voice:
        result["audio_base64_mp3"] = generate_voice_base64(
            result["safety_action"], result["warning_language_code"]
        )
    return result


@router.post("/scan/screenshot")
async def scan_screenshot(
    file: UploadFile = File(...),
    warning_language: str | None = Form(None),
    include_voice: bool = Form(True),
):
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=415, detail="Please upload a valid image file (PNG, JPG, JPEG, or WEBP).")

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="The uploaded image is empty.")

    ocr_result = ocr_service.extract_text(image_bytes)

    if not ocr_result["available"]:
        return {
            "ocr_available": False,
            "reason": ocr_result["reason"],
            "extracted_text": None,
            "analysis": None,
        }

    extracted_text = ocr_result["text"]
    if not extracted_text:
        return {
            "ocr_available": True,
            "reason": "OCR ran but found no readable text in this image.",
            "extracted_text": "",
            "analysis": None,
        }

    result = run_pipeline(extracted_text, warning_language=warning_language, input_type="screenshot")
    if include_voice:
        result["audio_base64_mp3"] = generate_voice_base64(
            result["safety_action"], result["warning_language_code"]
        )

    return {
        "ocr_available": True,
        "reason": None,
        "extracted_text": extracted_text,
        "ocr_engine": ocr_result.get("engine"),
        "analysis": result,
    }


@router.post("/scan/qr")
async def scan_qr(
    file: UploadFile = File(...),
    warning_language: str | None = Form(None),
    include_voice: bool = Form(True),
):
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=415, detail="Please upload a valid QR image file.")

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="The uploaded QR image is empty.")

    qr_result = qr_service.decode_qr(image_bytes)

    if not qr_result["available"]:
        return {
            "qr_available": False,
            "reason": qr_result["reason"],
            "decoded_text": None,
            "analysis": None,
        }

    decoded = qr_result["decoded_text"]
    if not decoded:
        return {
            "qr_available": True,
            "reason": qr_result["reason"] or "No QR code detected in the image.",
            "decoded_text": None,
            "decoder": qr_result.get("decoder"),
            "analysis": None,
        }

    result = run_pipeline(decoded, warning_language=warning_language, input_type="qr")
    if include_voice:
        result["audio_base64_mp3"] = generate_voice_base64(
            result["safety_action"], result["warning_language_code"]
        )

    return {
        "qr_available": True,
        "reason": None,
        "decoded_text": decoded,
        "analysis": result,
    }

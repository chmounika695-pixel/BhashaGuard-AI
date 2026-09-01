"""
Robust QR-code decoding for BhashaGuard.

The service uses two independent decoders:
1. pyzbar/ZBar when available.
2. OpenCV QRCodeDetector as a fallback and additional decoder.

Several preprocessing variants are tried because QR images commonly arrive as
screenshots, compressed WhatsApp images, resized images, or images with
non-ideal contrast.
"""
import io
from typing import Optional

try:
    from PIL import Image, ImageOps, ImageEnhance, ImageFilter
    _PIL_OK = True
except ImportError:
    _PIL_OK = False

try:
    from pyzbar.pyzbar import decode as zbar_decode, ZBarSymbol
    _PYZBAR_OK = True
except Exception:
    _PYZBAR_OK = False

try:
    import cv2
    import numpy as np
    _CV2_OK = True
except Exception:
    _CV2_OK = False


def is_available() -> bool:
    return _PYZBAR_OK or (_CV2_OK and _PIL_OK)


def _pil_variants(image: "Image.Image"):
    """Yield conservative image variants for QR decoding."""
    image = ImageOps.exif_transpose(image).convert("RGB")
    yield image

    # QR codes are often small in screenshots. Upscaling improves decoder
    # sampling without changing the underlying QR content.
    w, h = image.size
    for scale in (2, 3, 4):
        yield image.resize((w * scale, h * scale), Image.Resampling.LANCZOS)

    gray = ImageOps.grayscale(image)
    yield gray
    yield ImageOps.autocontrast(gray)
    yield ImageEnhance.Contrast(gray).enhance(1.8)
    yield gray.filter(ImageFilter.SHARPEN)

    # A larger grayscale version is useful for compressed screenshots.
    yield ImageOps.autocontrast(gray.resize((w * 3, h * 3), Image.Resampling.LANCZOS))


def _decode_with_pyzbar(image_bytes: bytes) -> Optional[str]:
    if not (_PYZBAR_OK and _PIL_OK):
        return None

    original = ImageOps.exif_transpose(Image.open(io.BytesIO(image_bytes)))
    for variant in _pil_variants(original):
        try:
            results = zbar_decode(variant, symbols=[ZBarSymbol.QRCODE])
        except Exception:
            continue
        for result in results:
            if result.data:
                return result.data.decode("utf-8", errors="replace").strip()
    return None


def _cv2_variants(image_bytes: bytes):
    if not (_CV2_OK and _PIL_OK):
        return

    image = ImageOps.exif_transpose(Image.open(io.BytesIO(image_bytes))).convert("RGB")
    arr = np.asarray(image)
    bgr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)

    variants = [bgr]
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    variants.append(gray)

    # Upscaling and contrast/threshold variants help with small QR images.
    for scale in (2, 3, 4):
        up = cv2.resize(bgr, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        variants.append(up)
        up_gray = cv2.cvtColor(up, cv2.COLOR_BGR2GRAY)
        variants.append(up_gray)
        variants.append(cv2.threshold(up_gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1])
        variants.append(cv2.adaptiveThreshold(
            up_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY, 31, 5
        ))

    variants.append(cv2.bitwise_not(gray))
    return variants


def _decode_with_cv2(image_bytes: bytes) -> Optional[str]:
    if not (_CV2_OK and _PIL_OK):
        return None

    detector = cv2.QRCodeDetector()

    for image in _cv2_variants(image_bytes):
        try:
            data, _, _ = detector.detectAndDecode(image)
            if data:
                return data.strip()
        except Exception:
            pass

        # OpenCV can decode multiple QR codes in one image.
        try:
            ok, decoded_info, _, _ = detector.detectAndDecodeMulti(image)
            if ok and decoded_info:
                for data in decoded_info:
                    if data:
                        return data.strip()
        except Exception:
            pass

    return None


def decode_qr(image_bytes: bytes) -> dict:
    if not image_bytes:
        return {
            "available": True,
            "decoded_text": None,
            "reason": "The uploaded image is empty.",
        }

    if not is_available():
        return {
            "available": False,
            "decoded_text": None,
            "reason": "QR decoding is unavailable. Install pyzbar and Pillow, or OpenCV and Pillow.",
        }

    errors = []

    # ZBar is normally the most reliable decoder for ordinary QR images.
    if _PYZBAR_OK:
        try:
            data = _decode_with_pyzbar(image_bytes)
            if data:
                return {"available": True, "decoded_text": data, "reason": None, "decoder": "pyzbar"}
        except Exception as exc:
            errors.append(f"pyzbar: {exc.__class__.__name__}: {exc}")

    # Always try OpenCV as a second independent decoder, even when pyzbar is
    # installed but cannot decode a particular image.
    if _CV2_OK:
        try:
            data = _decode_with_cv2(image_bytes)
            if data:
                return {"available": True, "decoded_text": data, "reason": None, "decoder": "opencv"}
        except Exception as exc:
            errors.append(f"opencv: {exc.__class__.__name__}: {exc}")

    if errors:
        return {
            "available": True,
            "decoded_text": None,
            "reason": "QR decoder could not read this image. " + "; ".join(errors),
        }

    return {
        "available": True,
        "decoded_text": None,
        "reason": "No QR code was detected. Try a clearer image with the complete QR code visible and a small white margin around it.",
    }

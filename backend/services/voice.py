"""
Text-to-speech generation for the voice-first warning feature. Extracted
into its own service so every route that needs audio (text scan,
screenshot scan, QR scan) calls the same function instead of duplicating
the gTTS error-handling.
"""
import base64
import io

SUPPORTED_TTS_LANGS = {"hi", "bn", "ta", "te", "kn", "en"}


def generate_voice_base64(text: str, language_code: str) -> str | None:
    """Returns a base64-encoded MP3, or None if TTS is unavailable/fails.
    Voice is always a nice-to-have — callers must never fail the whole
    request just because audio generation didn't work (e.g. no internet
    reaching Google's TTS endpoint)."""
    tts_lang = language_code.split("-")[0]
    if tts_lang not in SUPPORTED_TTS_LANGS:
        tts_lang = "en"

    try:
        from gtts import gTTS
    except ImportError:
        return None

    try:
        buf = io.BytesIO()
        gTTS(text=text, lang=tts_lang).write_to_fp(buf)
        return base64.b64encode(buf.getvalue()).decode("utf-8")
    except Exception:
        return None

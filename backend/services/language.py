"""
Language detection for BhashaGuard AI.

Handles three cases, which is the actual gap this project targets:
1. Native script text (Devanagari, Tamil, Telugu, Bengali, Kannada)
   -> detected via Unicode block ranges.
2. Romanized / code-mixed text ("Aapka bill overdue hai, click karein")
   -> flagged separately since standard language detectors misclassify
      this as plain English.
3. Native script mixed with English words in the same message
   ("Nimma account block agutte. KYC update madi immediately.")
   -> detected as script=Native, code_mixed=True, so the UI can show
      "Kannada + English" rather than just "Kannada".

This is intentionally heuristic (Unicode ranges + marker word lists),
not a trained classifier — it is fast, deterministic, and covers the
demo languages well. A trained multilingual model is listed as roadmap
in the README; claiming one here without training it would be the kind
of fabrication this project explicitly avoids.
"""
import re
from langdetect import detect, DetectorFactory, LangDetectException

DetectorFactory.seed = 0

# Unicode block ranges for supported Indian scripts
SCRIPT_RANGES = {
    "hi": (0x0900, 0x097F),  # Devanagari (Hindi, Marathi)
    "bn": (0x0980, 0x09FF),  # Bengali
    "ta": (0x0B80, 0x0BFF),  # Tamil
    "te": (0x0C00, 0x0C7F),  # Telugu
    "kn": (0x0C80, 0x0CFF),  # Kannada
}

LANGUAGE_NAMES = {
    "hi": "Hindi", "bn": "Bengali", "ta": "Tamil", "te": "Telugu",
    "kn": "Kannada", "en": "English",
    "hi-latn": "Hindi", "ta-latn": "Tamil", "kn-latn": "Kannada",
    "te-latn": "Telugu", "bn-latn": "Bengali",
}

# Marker words for romanized/code-mixed regional phishing lures — the fast
# heuristic tier. The LLM content-risk tier (when a key is configured) does
# the deeper contextual read on top of this.
ROMANIZED_MARKERS = {
    "hi-latn": [
        "aapka", "aapke", "kripya", "turant", "band ho jayega", "bill overdue",
        "click karein", "khata band", "otp bhejein", "verify karein",
        "jaldi", "abhi", "warna", "ho jayega", "ho jayegi", "karein",
    ],
    "ta-latn": [
        "ungal", "seivom", "kudirunthu", "urimai", "kanakku", "clickpannunga",
        "panunga", "aagum", "click pannunga",
    ],
    "kn-latn": [
        "nimma", "agutte", "agide", "aagutte", "madi", "maadi", "immediately",
        "kyc update madi", "block agutte",
    ],
    "te-latn": [
        "meeru", "cheyandi", "cheyyandi", "avutundi", "chestunnaru", "ventane",
    ],
    "bn-latn": [
        "apnar", "korun", "hoye jabe", "ekhoni", "bondho", "taratari",
    ],
}

# Common English function words used to decide whether romanized/native-script
# text is genuinely code-mixed with English, vs. just containing an isolated
# loanword (e.g. "OTP", "KYC" appear in almost every message regardless).
ENGLISH_FUNCTION_WORDS = {
    "the", "is", "will", "your", "you", "please", "account", "click",
    "link", "immediately", "now", "update", "verify", "and", "to", "for",
    "be", "has", "have", "not", "this", "that", "with",
}


def detect_script(text: str) -> str | None:
    """Return an ISO code if the text is dominantly in a known Indic script."""
    counts = {code: 0 for code in SCRIPT_RANGES}
    for ch in text:
        cp = ord(ch)
        for code, (lo, hi) in SCRIPT_RANGES.items():
            if lo <= cp <= hi:
                counts[code] += 1
    best = max(counts, key=counts.get)
    if counts[best] >= 3:
        return best
    return None


def detect_romanized(text: str) -> str | None:
    """Heuristic check for romanized/code-mixed regional text."""
    lowered = text.lower()
    best_code, best_hits = None, 0
    for code, markers in ROMANIZED_MARKERS.items():
        hits = sum(1 for m in markers if m in lowered)
        if hits > best_hits:
            best_code, best_hits = code, hits
    return best_code if best_hits >= 1 else None


def _has_english_mix(text: str) -> bool:
    words = re.findall(r"[a-zA-Z]+", text.lower())
    hits = sum(1 for w in words if w in ENGLISH_FUNCTION_WORDS)
    return hits >= 2


def detect_language(text: str) -> dict:
    script_lang = detect_script(text)
    if script_lang:
        code_mixed = _has_english_mix(text)
        name = LANGUAGE_NAMES.get(script_lang, script_lang)
        return {
            "language_code": script_lang,
            "language_name": f"{name} + English" if code_mixed else name,
            "script": "Native",
            "code_mixed": code_mixed,
            "mode": "native_script",
        }

    romanized_lang = detect_romanized(text)
    if romanized_lang:
        code_mixed = _has_english_mix(text)
        name = LANGUAGE_NAMES.get(romanized_lang, romanized_lang)
        return {
            "language_code": romanized_lang,
            "language_name": f"{name} + English" if code_mixed else f"{name} (Romanized)",
            "script": "Romanized",
            "code_mixed": code_mixed,
            "mode": "romanized_code_mixed",
        }

    try:
        code = detect(text)
    except LangDetectException:
        code = "en"

    return {
        "language_code": code,
        "language_name": LANGUAGE_NAMES.get(code, code),
        "script": "Native" if code != "en" else "Latin",
        "code_mixed": False,
        "mode": "standard",
    }

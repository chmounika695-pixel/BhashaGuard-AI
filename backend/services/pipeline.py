"""
The one shared pipeline every entry point runs through: web UI, browser
extension, WhatsApp bot prototype, screenshot OCR, QR decode. Keeping
this in one place is what "modular pipeline" means here — each route
just gets text into this function differently.
"""
import re

from services.language import detect_language
from services.content_risk import analyze_content, native_explanation
from services.url_heuristics import analyze_url, resolve_short_url, SHORTENERS, _domain_of
from services.fusion import fuse
from services.translation import get_safety_action, SUPPORTED_WARNING_LANGUAGES, WARNING_LANGUAGE_NAMES
from services import storage

URL_PATTERN = re.compile(r"https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9\-]+\.[a-z]{2,}(?:/[^\s]*)?")


def run_pipeline(text: str, warning_language: str | None = None, input_type: str = "text", store_history: bool = True) -> dict:
    text = text.strip()

    language = detect_language(text)
    content_result = analyze_content(text, language["language_code"])

    url_match = URL_PATTERN.search(text)
    url_result = None
    if url_match:
        raw_url = url_match.group(0).rstrip(".,);]}")
        url_result = analyze_url(raw_url)

        # QR codes frequently encode a short URL. A shortener must not be
        # treated as SAFE merely because its own domain looks ordinary.
        # Resolve it when possible, then score the actual destination.
        domain = _domain_of(raw_url)
        if domain in SHORTENERS:
            resolution = resolve_short_url(raw_url)
            url_result["original_url"] = raw_url
            url_result["redirect_chain"] = resolution.get("redirect_chain", [])
            url_result["resolved_url"] = resolution.get("resolved_url")
            if resolution.get("resolved_url") and resolution["resolved_url"] != raw_url:
                final_result = analyze_url(resolution["resolved_url"])
                url_result["resolved_url_analysis"] = final_result
                url_result["flags"].append(f"Short URL resolves to: {resolution['resolved_url']}")
                url_result["flags"].extend(final_result.get("flags", []))
                url_result["url_risk_score"] = max(
                    url_result.get("url_risk_score", 0),
                    final_result.get("url_risk_score", 0)
                )
            elif resolution.get("error"):
                url_result["resolution_error"] = resolution["error"]
                url_result["flags"].append("Destination is hidden behind a short URL and could not be verified.")
                # Keep short URLs at least SUSPICIOUS, never SAFE.
                url_result["url_risk_score"] = max(url_result.get("url_risk_score", 0), 45)

    verdict = fuse(content_result, url_result)

    # The content-risk explanation is generated BEFORE the URL signal is
    # known, so it can undersell risk when the message text is mild but
    # the URL is the dangerous part (e.g. a QR/URL-only scan). Re-derive
    # the native-language explanation from the FINAL fused tier so what
    # the user reads always matches the verdict they're shown.
    final_is_risky = verdict["tier"] != "SAFE"
    verdict["explanation_native"] = native_explanation(language["language_code"], final_is_risky)

    warn_lang = warning_language or language["language_code"].split("-")[0]
    if warn_lang not in SUPPORTED_WARNING_LANGUAGES:
        warn_lang = "en"
    is_safe = verdict["tier"] == "SAFE"
    safety_action = get_safety_action(verdict["category"], warn_lang, is_safe)

    result = {
        "input_text": text,
        "language": language,
        "content_analysis": content_result,
        "url_analysis": url_result,
        "verdict": verdict,
        "warning_language": WARNING_LANGUAGE_NAMES.get(warn_lang, warn_lang),
        "warning_language_code": warn_lang,
        "safety_action": safety_action,
    }

    if store_history:
        entry = storage.add_history_entry(input_type, text, language, verdict)
        result["history_id"] = entry["id"]

    return result

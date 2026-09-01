"""
Combines URL-risk and content-risk signals into one final verdict, using
the SAFE / SUSPICIOUS / HIGH RISK / PHISHING four-tier system.

Uses noisy-OR combination instead of a weighted average: either signal
being strongly risky on its own is enough to raise the verdict, rather
than a strong signal getting diluted by a quiet one (e.g. a bare
phishing URL pasted with no surrounding message text must still score
as risky on the URL signal alone).

Also assembles the "Threat Breakdown" — every sub-score that fed into
the final number, so the result is explainable rather than a bare
percentage.
"""

TIERS = [
    (81, "PHISHING", "🔴"),
    (61, "HIGH RISK", "🟠"),
    (31, "SUSPICIOUS", "🟡"),
    (0, "SAFE", "🟢"),
]


def _tier_for(score: int) -> tuple[str, str]:
    for threshold, label, badge in TIERS:
        if score >= threshold:
            return label, badge
    return "SAFE", "🟢"


def fuse(content_result: dict, url_result: dict | None) -> dict:
    content_score = content_result.get("risk_score", 0)
    url_score = url_result.get("url_risk_score", 0) if url_result else 0
    sub_scores = content_result.get("sub_scores", {})

    content_p = min(max(content_score, 0), 100) / 100
    url_p = min(max(url_score, 0), 100) / 100
    combined_p = 1 - (1 - content_p) * (1 - url_p)
    final_score = round(combined_p * 100)

    level, badge = _tier_for(final_score)

    reasons = list(content_result.get("reasons", []))
    if url_result:
        reasons.extend(url_result.get("flags", []))

    threat_breakdown = {
        "Social Engineering": sub_scores.get("social_engineering", 0),
        "Credential Risk": sub_scores.get("credential_risk", 0),
        "Impersonation": sub_scores.get("impersonation", 0),
        "Financial Request": sub_scores.get("financial_request", 0),
        "Content Risk": content_score,
        "URL Risk": url_score,
        "Overall Risk": final_score,
    }

    # Backward-compatible 3-tier alias (older UI/tests expect this shape).
    legacy_level = "danger" if final_score >= 60 else ("caution" if final_score >= 25 else "safe")

    return {
        "final_risk_level": legacy_level,
        "final_risk_score": final_score,
        "badge": badge,
        "tier": level,
        "threat_breakdown": threat_breakdown,
        "category": content_result.get("category", "Other"),
        "indicators": content_result.get("indicators", []),
        "attacker_goal": content_result.get("attacker_goal", []),
        "reasons": reasons,
        "explanation_native": content_result.get("explanation_native", ""),
    }

"""
Content risk scoring — multi-signal, not a single "ask an LLM" call.

Architecture (deliberately, per the project's own rule against collapsing
everything into one model call):

1. `classify_and_score()` — a deterministic, rule-based classifier that
   ALWAYS runs. It produces the scam category, sub-signal scores (social
   engineering/urgency, credential-request, impersonation, financial-
   request), attacker-goal list, and indicator list. This is transparent
   and explainable: every number traces back to a matched keyword group,
   not a black-box call.

2. The LLM (Groq, optional) is layered ON TOP of that — it only refines
   the overall risk_score and writes the native-language explanation. If
   no GROQ_API_KEY is set, or the call fails, the deterministic layer's
   own score and a templated native-language explanation are used
   instead. The category/sub-scores/indicators are identical either way,
   since they never depended on the LLM to begin with.
"""
import json
import os
import re

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "qwen/qwen3.6-27b")

# ---------------------------------------------------------------------------
# Deterministic rule-based layer — category + sub-signal scoring
# ---------------------------------------------------------------------------

CATEGORY_KEYWORDS = {
    "Banking": [
        "bank account", "net banking", "ifsc", "account number", "debit card", "credit card", "khata",
        "बैंक खाता", "खाता", "வங்கி கணக்கு", "கணக்கு", "బ్యాంక్ ఖాతా", "ఖాతా",
        "ব্যাংক অ্যাকাউন্ট", "অ্যাকাউন্ট", "ಬ್ಯಾಂಕ್ ಖಾತೆ", "ಖಾತೆ",
    ],
    "UPI/Payment": ["upi", "paytm", "phonepe", "gpay", "google pay", "payment failed", "transaction failed"],
    "KYC": ["kyc", "know your customer", "re-kyc", "kyc update", "kyc verify", "kyc expire", "केवाईसी"],
    "Utility Payment": ["electricity bill", "power supply", "water bill", "gas bill", "disconnect", "connection band", "bill overdue"],
    "Government": ["income tax", "aadhaar", "pan card", "uidai", "government scheme", "subsidy", "gst"],
    "Job Scam": ["job offer", "work from home", "part time job", "hiring now", "interview selected", "salary per day", "earn from home"],
    "Scholarship": ["scholarship", "fee waiver", "education grant", "student loan approved"],
    "Delivery": ["courier", "parcel", "delivery failed", "shipment", "customs duty", "tracking id", "package held"],
    "Lottery/Reward": [
        "lottery", "prize", "you have won", "winner", "lucky draw", "kbc", "congratulations you",
        "लॉटरी", "जीते हैं", "बधाई हो", "லாட்டரி", "வென்றுள்ளீர்கள்", "வாழ்த்துக்கள்",
        "లాటరీ", "గెలుచుకున్నారు", "అభినందనలు", "লটারি", "জিতেছেন", "অভিনন্দন",
        "ಲಾಟರಿ", "ಗೆದ್ದಿದ್ದೀರಿ", "ಅಭಿನಂದನೆಗಳು",
    ],
    "Investment": ["investment", "stock tips", "trading profit", "crypto", "guaranteed returns", "mutual fund", "double your money"],
    "Credential Theft": ["password", "login id", "user id", "share your otp", "share your pin"],
    "Account Suspension": [
        "account suspended", "account blocked", "account will be closed", "block ho jayega", "band ho jayega",
        "block agutte", "suspend", "बंद हो जाएगा", "ब्लॉक हो जाएगा", "முடக்கப்படும்", "தடுக்கப்படும்",
        "బ్లాక్ చేయబడుతుంది", "నిలిపివేయబడుతుంది", "বন্ধ হয়ে যাবে", "ব্লক হয়ে যাবে",
        "ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ", "ಸ್ಥಗಿತಗೊಳ್ಳುತ್ತದೆ",
    ],
}

URGENCY_WORDS = [
    "turant", "jaldi", "immediately", "urgent", "abhi", "act now", "last chance",
    "expire", "within 24 hours", "today only", "ventane", "madi", "maadi",
    "taratari", "ekhoni",
    "तुरंत", "जल्दी", "अभी", "உடனடியாக", "இப்போது", "వెంటనే", "ఇప్పుడు",
    "এখনই", "তাড়াতাড়ি", "ತಕ್ಷಣ", "ಈಗಲೇ",
]
CREDENTIAL_WORDS = ["otp", "pin", "cvv", "password", "login id", "user id", "share your"]
IMPERSONATION_BRANDS = [
    "sbi", "hdfc", "icici", "axis bank", "paytm", "phonepe", "uidai",
    "income tax", "irctc", "whatsapp", "google", "amazon", "flipkart",
]
FINANCIAL_WORDS = ["pay now", "payment", "transfer", "fee", "fine", "penalty", "refund", "claim now", "deposit"]


def _hit_ratio_score(text_lower: str, words: list) -> tuple[int, list]:
    hits = [w for w in words if w in text_lower]
    score = min(len(hits) * 35, 100)
    return score, hits


def classify_and_score(text: str) -> dict:
    lowered = text.lower()

    category, best_hits = "Other", 0
    matched_category_words = []
    for cat, words in CATEGORY_KEYWORDS.items():
        hits = [w for w in words if w in lowered]
        if len(hits) > best_hits:
            category, best_hits = cat, len(hits)
            matched_category_words = hits
    if best_hits == 0:
        category = "Other"

    urgency_score, urgency_hits = _hit_ratio_score(lowered, URGENCY_WORDS)
    credential_score, credential_hits = _hit_ratio_score(lowered, CREDENTIAL_WORDS)
    impersonation_score, impersonation_hits = _hit_ratio_score(lowered, IMPERSONATION_BRANDS)
    financial_score, financial_hits = _hit_ratio_score(lowered, FINANCIAL_WORDS)

    indicators = []
    if urgency_hits:
        indicators.append("Urgency / pressure tactics")
    if impersonation_hits:
        indicators.append(f"Possible impersonation of: {', '.join(sorted(set(impersonation_hits)))}")
    if category != "Other":
        indicators.append(f"{category} scam pattern")
    if credential_hits:
        indicators.append("Credential request (OTP/PIN/password)")
    if financial_hits:
        indicators.append("Payment / money-transfer request")

    attacker_goal = []
    if credential_hits:
        attacker_goal.append("OTP / PIN / password")
    if "bank" in lowered or category == "Banking":
        attacker_goal.append("Banking credentials")
    if category == "KYC":
        attacker_goal.append("KYC / identity information")
    if financial_hits:
        attacker_goal.append("Payment / money transfer")
    if not attacker_goal and best_hits:
        attacker_goal.append("Personal information")

    # Overall rule-based score: noisy-OR across the sub-signals (a single
    # strong signal — e.g. a bare OTP request — must not get diluted into
    # near-zero just because the other signals are quiet, the same class
    # of bug already fixed once for URL/content fusion), then a further
    # noisy-OR bump if a scam category matched at all.
    sub_probs = [urgency_score / 100, credential_score / 100, impersonation_score / 100, financial_score / 100]
    combined = 1.0
    for p in sub_probs:
        combined *= (1 - p)
    combined = 1 - combined  # noisy-OR of the four sub-signals

    if category != "Other":
        combined = 1 - (1 - combined) * (1 - 0.40)  # category match contributes like a 40-point signal

    rule_score = round(min(combined * 100, 100))

    all_hits = list(dict.fromkeys(urgency_hits + credential_hits + impersonation_hits + financial_hits + matched_category_words))

    return {
        "category": category,
        "indicators": indicators,
        "attacker_goal": attacker_goal,
        "sub_scores": {
            "social_engineering": urgency_score,
            "credential_risk": credential_score,
            "impersonation": impersonation_score,
            "financial_request": financial_score,
        },
        "rule_based_risk_score": rule_score,
        "matched_keywords": all_hits[:6],
    }


# ---------------------------------------------------------------------------
# LLM layer (optional) — contextual risk_score refinement + native explanation
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are BhashaGuard AI, a phishing-detection assistant for Indian \
regional-language users. You will be given a message (possibly in Hindi, Tamil, \
Telugu, Bengali, Kannada, romanized/code-mixed Indian languages, or English).

Analyze it for phishing / scam intent: urgency pressure, fake KYC or utility-bill \
threats, requests for OTP/PIN/bank details, prize or lottery claims, impersonation \
of banks/government/delivery services, suspicious links.

Respond with ONLY a JSON object, no other text, in this exact shape:
{
  "risk_score": <integer 0-100>,
  "reasons": ["short reason 1", "short reason 2"],
  "explanation_native": "<one or two sentence explanation, written in the SAME \
language/script as the input message, in plain non-technical words a low-literacy \
user can understand>"
}"""

# Native-language explanations for the offline/templated path, so the demo
# stays genuinely multilingual even without an LLM key.
FALLBACK_EXPLANATIONS = {
    "hi": {"risky": "यह संदेश जल्दबाजी और धोखाधड़ी में इस्तेमाल होने वाली भाषा का उपयोग करता है। किसी भी लिंक पर क्लिक न करें और OTP या बैंक विवरण साझा न करें।",
           "safe": "इस संदेश में सामान्य धोखाधड़ी के लक्षण नहीं दिखते, फिर भी लिंक और व्यक्तिगत जानकारी साझा करते समय सतर्क रहें।"},
    "hi-latn": {"risky": "Yeh message jaldbaazi aur scam mein istemal hone wali bhasha ka upyog karta hai. Kisi bhi link par click na karein aur OTP ya bank details share na karein.",
                "safe": "Is message mein scam ke common signs nahi dikhte, phir bhi links aur personal details share karte waqt savdhaan rahein."},
    "ta": {"risky": "இந்த செய்தி ஏமாற்று வேலைகளுக்கு பயன்படுத்தப்படும் அவசர மொழியைப் பயன்படுத்துகிறது. எந்த இணைப்பையும் கிளிக் செய்யாதீர்கள், OTP அல்லது வங்கி விவரங்களைப் பகிராதீர்கள்.",
           "safe": "இந்த செய்தியில் பொதுவான ஏமாற்று அறிகுறிகள் இல்லை, ஆனாலும் இணைப்புகள் மற்றும் தனிப்பட்ட தகவல்களைப் பகிரும்போது எச்சரிக்கையாக இருங்கள்."},
    "ta-latn": {"risky": "Indha message-la urgent mozhi use panniruken, ithu scam maadhiri irukku. Edhavadhu link click pannadheenga, OTP illa bank details share pannadheenga.",
                "safe": "Indha message-la common scam signs illa, aanaalum links matrum personal details share pannum bodhu careful ah irunga."},
    "te": {"risky": "ఈ సందేశం మోసానికి సంబంధించిన అత్యవసర భాషను ఉపయోగిస్తోంది. ఏ లింక్‌పై క్లిక్ చేయవద్దు, OTP లేదా బ్యాంక్ వివరాలు షేర్ చేయవద్దు.",
           "safe": "ఈ సందేశంలో సాధారణ మోసపు సంకేతాలు కనిపించడం లేదు, అయినప్పటికీ లింక్‌లు మరియు వ్యక్తిగత సమాచారాన్ని పంచుకునేటప్పుడు జాగ్రత్తగా ఉండండి."},
    "bn": {"risky": "এই বার্তায় জরুরি ও প্রতারণামূলক ভাষা ব্যবহার করা হয়েছে। কোনো লিংকে ক্লিক করবেন না এবং OTP বা ব্যাংক বিবরণ শেয়ার করবেন না।",
           "safe": "এই বার্তায় সাধারণ প্রতারণার লক্ষণ দেখা যাচ্ছে না, তবুও লিঙ্ক এবং ব্যক্তিগত তথ্য শেয়ার করার সময় সতর্ক থাকুন।"},
    "kn": {"risky": "ಈ ಸಂದೇಶವು ವಂಚನೆಗೆ ಸಂಬಂಧಿಸಿದ ತುರ್ತು ಭಾಷೆಯನ್ನು ಬಳಸುತ್ತದೆ. ಯಾವುದೇ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ, OTP ಅಥವಾ ಬ್ಯಾಂಕ್ ವಿವರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
           "safe": "ಈ ಸಂದೇಶದಲ್ಲಿ ಸಾಮಾನ್ಯ ವಂಚನೆಯ ಚಿಹ್ನೆಗಳು ಕಂಡುಬರುತ್ತಿಲ್ಲ, ಆದರೂ ಲಿಂಕ್‌ಗಳು ಮತ್ತು ವೈಯಕ್ತಿಕ ಮಾಹಿತಿಯನ್ನು ಹಂಚಿಕೊಳ್ಳುವಾಗ ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ."},
    "en": {"risky": "This message uses urgent language and requests typical of scams. Do not click any links or share OTP/bank details.",
           "safe": "This message does not show common phishing patterns, but always stay cautious with links and personal details."},
}

# Aliases for the -latn codes so a template lookup for e.g. "kn-latn" or
# "te-latn" (which have no dedicated romanized template written) falls back
# to the native-script template of the same language rather than English.
_TEMPLATE_ALIAS = {"kn-latn": "kn", "te-latn": "te", "bn-latn": "bn"}


def native_explanation(language_code: str, is_risky: bool) -> str:
    key = _TEMPLATE_ALIAS.get(language_code, language_code)
    templates = FALLBACK_EXPLANATIONS.get(key, FALLBACK_EXPLANATIONS["en"])
    return templates["risky"] if is_risky else templates["safe"]


# Internal alias kept for the one call site inside this module.
_native_explanation = native_explanation


def _call_groq(text: str) -> dict:
    from groq import Groq

    client = Groq(api_key=GROQ_API_KEY)
    completion = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
        temperature=0.2,
        max_tokens=300,
    )
    raw = completion.choices[0].message.content.strip()
    raw = re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    return json.loads(raw)


def analyze_content(text: str, language_code: str = "en") -> dict:
    rule_result = classify_and_score(text)
    is_risky = rule_result["rule_based_risk_score"] >= 25

    result = {
        "risk_score": rule_result["rule_based_risk_score"],
        "reasons": rule_result["matched_keywords"] or ["No strong phishing markers detected"],
        "explanation_native": _native_explanation(language_code, is_risky),
        "category": rule_result["category"],
        "indicators": rule_result["indicators"],
        "attacker_goal": rule_result["attacker_goal"],
        "sub_scores": rule_result["sub_scores"],
        "engine": "rule_based",
    }

    if GROQ_API_KEY:
        try:
            llm_data = _call_groq(text)
            # LLM refines score/reasons/explanation only — category and
            # sub-scores stay deterministic (see module docstring).
            result["risk_score"] = int(llm_data.get("risk_score", result["risk_score"]))
            result["reasons"] = llm_data.get("reasons", result["reasons"])
            result["explanation_native"] = llm_data.get("explanation_native", result["explanation_native"])
            result["engine"] = f"rule_based+groq:{GROQ_MODEL}"
        except Exception as exc:
            result["engine"] = f"rule_based (groq_error: {exc.__class__.__name__})"

    return result

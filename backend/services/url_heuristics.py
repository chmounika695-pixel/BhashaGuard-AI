"""
Lightweight URL / domain heuristics.

Deliberately avoids live WHOIS lookups (slow, rate-limited, unreliable
during a live demo) in favor of fast, deterministic checks:
  - typosquat distance against a known brand list
  - suspicious TLDs commonly abused in phishing kits
  - link-shortener detection (hides real destination)
  - raw-IP-address URLs
"""
import re
import socket
import ipaddress
import requests
from urllib.parse import urlparse, urljoin

KNOWN_BRANDS = [
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "paytm.com", "phonepe.com", "google.com", "amazon.in", "flipkart.com",
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in", "whatsapp.com",
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".buzz", ".click", ".gq", ".tk", ".ml", ".cf", ".work"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "qrco.de", "qr1.be", "rebrand.ly", "shorturl.at"}

IP_URL_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def levenshtein_distance(a: str, b: str) -> int:
    """Pure-Python edit distance — no compiled dependency required."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                curr_row[j - 1] + 1,      # insertion
                prev_row[j] + 1,          # deletion
                prev_row[j - 1] + cost,   # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


def _domain_of(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return urlparse(url).netloc.lower().split(":")[0]


def _path_and_query_of(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    return (parsed.path + "?" + parsed.query).lower()


PATH_SCAM_WORDS = [
    "login", "signin", "verify", "secure", "account", "confirm", "update",
    "authenticate", "password", "security-alert", "suspended", "kyc", "otp",
]
REDIRECT_PARAM_PATTERN = re.compile(r"(?:^|[?&])(redirect|return|next|url|continue|target)=", re.IGNORECASE)


def _brand_core(brand: str) -> str:
    """Strip the TLD/suffix so we compare 'hdfcbank' not 'hdfcbank.com'."""
    return brand.split(".")[0]


def analyze_url(url: str) -> dict:
    domain = _domain_of(url)
    path_query = _path_and_query_of(url)
    flags = []
    score = 0  # 0 = clean, higher = riskier

    # Path/query scam signals apply regardless of domain trust — a
    # legitimate-looking or even genuinely trusted domain can still be
    # used as an open-redirect launchpad (e.g. "trusted.com/redirect?
    # url=evil.com"), and a placeholder/unknown domain with "login",
    # "verify", "redirect=" stuffed into the path is a classic phishing-
    # kit pattern even when the domain itself has no other red flags.
    path_hits = [w for w in PATH_SCAM_WORDS if w in path_query]
    if len(path_hits) >= 2:
        flags.append(f"URL path/query contains multiple scam-pattern words ({', '.join(path_hits[:4])})")
        score += 35
    elif len(path_hits) == 1:
        flags.append(f"URL path/query contains scam-pattern wording ('{path_hits[0]}')")
        score += 15

    if REDIRECT_PARAM_PATTERN.search(path_query):
        flags.append("URL contains an open-redirect-style parameter (redirect=/return=/next=/url=)")
        score += 30

    # Exact / subdomain match against a known brand = trusted domain, but
    # path/query signals above still apply (see comment above) — only the
    # domain-level checks below are skipped.
    is_known_brand = any(domain == brand or domain.endswith("." + brand) for brand in KNOWN_BRANDS)
    if is_known_brand:
        matched_brand = next(b for b in KNOWN_BRANDS if domain == b or domain.endswith("." + b))
        flags.insert(0, f"Matches known legitimate domain '{matched_brand}'")
        return {
            "domain": domain,
            "url_risk_score": min(score, 100),
            "flags": flags,
        }

    # Typosquat check: compare each hyphen/dot-separated token in the domain
    # (not just the whole string) against known brand names. This catches
    # "hdfcbnk-verify.xyz" as close to "hdfcbank" even though the full
    # domain string is a poor match — the tokens are what matter.
    domain_body = re.split(r"\.(com|in|co\.in|org|net|xyz|top|buzz|click|gq|tk|ml|cf|work)$", domain)[0]
    tokens = re.split(r"[-.]", domain_body)

    closest_brand, closest_dist = None, 999
    for brand in KNOWN_BRANDS:
        core = _brand_core(brand)
        for token in tokens + [domain_body]:
            if len(token) < 5:  # too short for edit-distance matching to be meaningful
                continue
            dist = levenshtein_distance(token, core)
            if dist < closest_dist:
                closest_brand, closest_dist = brand, dist

    if 0 < closest_dist <= 2:
        flags.append(f"Domain '{domain}' closely resembles '{closest_brand}' (possible typosquat)")
        score += 55

    tld = "." + domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Uses a TLD ({tld}) frequently abused in phishing kits")
        score += 40

    if domain in SHORTENERS:
        flags.append("Uses a link shortener that hides the real destination")
        # A shortened URL hides its real destination. It should never be
        # presented as SAFE when the destination has not been verified.
        score += 45

    if IP_URL_PATTERN.match(domain):
        flags.append("URL uses a raw IP address instead of a domain name")
        score += 45

    # Extra lexical signal: scam-pattern words stitched into the domain
    # itself (very common in fake bill/KYC/refund links).
    scam_words = ["verify", "update", "kyc", "refund", "claim", "reward", "block", "suspend", "secure-", "login-"]
    if any(w in domain_body for w in scam_words):
        flags.append(f"Domain contains scam-pattern wording ('{domain_body}')")
        score += 25

    return {
        "domain": domain,
        "url_risk_score": min(score, 100),
        "flags": flags,
    }


def _host_is_public(host: str) -> bool:
    """Reject loopback/private/link-local destinations to avoid SSRF."""
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                return False
        return True
    except Exception:
        return False


def resolve_short_url(url: str, max_hops: int = 5, timeout: float = 4.0) -> dict:
    """Safely follow HTTP redirects for short URLs and return the final URL.

    Only public HTTP(S) hosts are contacted. Response bodies are not downloaded.
    This is intentionally bounded for a live phishing-analysis application.
    """
    current = url.strip()
    chain = [current]
    session = requests.Session()
    session.headers.update({"User-Agent": "BhashaGuard-SafeURLResolver/1.0"})

    for _ in range(max_hops):
        parsed = urlparse(current if "://" in current else "https://" + current)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return {"resolved_url": None, "redirect_chain": chain, "error": "Unsupported URL scheme or missing host."}
        host = parsed.hostname.lower()
        if not _host_is_public(host):
            return {"resolved_url": None, "redirect_chain": chain, "error": "Destination host could not be safely verified."}

        try:
            # stream=True prevents downloading an arbitrary page body.
            response = session.get(current, allow_redirects=False, stream=True, timeout=timeout)
            location = response.headers.get("location")
            response.close()
        except requests.RequestException as exc:
            return {"resolved_url": None, "redirect_chain": chain, "error": f"Redirect lookup failed: {exc.__class__.__name__}."}

        if not location or response.status_code not in {301, 302, 303, 307, 308}:
            return {
                "resolved_url": current,
                "redirect_chain": chain,
                "error": None,
                "status_code": response.status_code,
            }

        current = urljoin(current, location)
        chain.append(current)

    return {"resolved_url": None, "redirect_chain": chain, "error": "Too many redirects."}

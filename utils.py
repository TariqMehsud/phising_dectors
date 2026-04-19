"""
utils.py - Helper functions for Phishing Email Detector
"""

import re
import os
import json
import hashlib
import datetime
import tldextract
import urllib.parse
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR / "data"
MODEL_DIR  = BASE_DIR / "models"
REPORT_DIR = BASE_DIR / "reports"
LOG_FILE   = DATA_DIR / "scan_history.json"

for d in (DATA_DIR, MODEL_DIR, REPORT_DIR):
    d.mkdir(exist_ok=True)

# ── Phishing-signal dictionaries ─────────────────────────────────────────────
URGENT_KEYWORDS = [
    "urgent", "immediate", "action required", "verify now", "suspended",
    "account locked", "click here", "confirm your", "update your",
    "expires soon", "limited time", "act now", "immediately",
    "security alert", "unauthorized", "suspicious activity", "verify identity",
    "your account will be", "failure to", "within 24 hours", "within 48 hours",
    "respond immediately", "important notice", "final warning", "last chance",
]

FINANCIAL_KEYWORDS = [
    "bank", "paypal", "credit card", "debit card", "ssn", "social security",
    "routing number", "account number", "wire transfer", "bitcoin", "cryptocurrency",
    "investment", "prize", "winner", "lottery", "million dollars", "inheritance",
    "fund transfer", "unclaimed funds", "beneficiary",
]

CREDENTIAL_KEYWORDS = [
    "password", "username", "login", "sign in", "credentials",
    "enter your", "provide your", "submit your", "confirm your password",
    "reset password", "forgot password", "update password",
]

THREAT_KEYWORDS = [
    "hacked", "virus", "malware", "compromised", "breach", "stolen",
    "arrest", "legal action", "lawsuit", "irs", "fbi", "police",
    "court order", "subpoena", "penalty", "fine",
]

KNOWN_PHISHING_DOMAINS = {
    "paypa1.com", "arnazon.com", "g00gle.com", "micosoft.com",
    "faceb00k.com", "netf1ix.com", "app1e.com", "rn.com",
    "paypal-secure.com", "secure-paypal.com", "amazon-security.com",
    "appleid-verify.com", "microsoft-alert.com", "google-verify.net",
}

LEGITIMATE_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "apple.com",
    "amazon.com", "paypal.com", "facebook.com", "twitter.com",
    "linkedin.com", "github.com", "stackoverflow.com",
}

# ── URL helpers ───────────────────────────────────────────────────────────────

def extract_urls(text: str) -> list[str]:
    """Extract all URLs from email text."""
    pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
    urls = re.findall(pattern, text, re.IGNORECASE)
    return list(set(urls))


def extract_domain(url: str) -> str:
    """Extract registered domain from URL."""
    try:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        return ""


def is_ip_url(url: str) -> bool:
    """Check if URL uses IP address instead of domain."""
    pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    return bool(re.match(pattern, url))


def has_url_shortener(url: str) -> bool:
    """Detect URL shorteners."""
    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "buff.ly", "rebrand.ly", "short.io", "rb.gy", "cutt.ly",
        "tiny.cc", "is.gd", "cli.gs", "pic.gd", "su.pr",
    }
    domain = extract_domain(url)
    return domain in shorteners


def check_url_mismatch(display_text: str, actual_url: str) -> bool:
    """Check if displayed text URL differs from href URL."""
    if not display_text or not actual_url:
        return False
    try:
        text_lower = display_text.lower()
        actual_lower = actual_url.lower()
        if text_lower.startswith(("http", "www")):
            text_domain = extract_domain(text_lower)
            actual_domain = extract_domain(actual_lower)
            return text_domain != actual_domain and bool(text_domain)
    except Exception:
        pass
    return False


def count_subdomains(url: str) -> int:
    """Count number of subdomains (excessive subdomains = suspicious)."""
    try:
        ext = tldextract.extract(url)
        if ext.subdomain:
            return len(ext.subdomain.split("."))
    except Exception:
        pass
    return 0


def url_has_at_symbol(url: str) -> bool:
    """@ in URL is used to trick parsers."""
    parsed = urllib.parse.urlparse(url)
    return "@" in parsed.netloc


def calculate_url_entropy(url: str) -> float:
    """Shannon entropy of URL path – high entropy = random/obfuscated."""
    import math
    path = urllib.parse.urlparse(url).path
    if not path:
        return 0.0
    freq = {}
    for c in path:
        freq[c] = freq.get(c, 0) + 1
    length = len(path)
    entropy = -sum((f / length) * math.log2(f / length) for f in freq.values())
    return round(entropy, 3)

# ── Email helpers ─────────────────────────────────────────────────────────────

def extract_sender_domain(from_header: str) -> str:
    """Extract domain from From: header."""
    match = re.search(r'@([\w.-]+)', from_header)
    return match.group(1).lower() if match else ""


def check_sender_spoofing(from_header: str, reply_to: str) -> dict:
    """Detect sender spoofing patterns."""
    result = {"spoofed": False, "reason": ""}
    from_domain = extract_sender_domain(from_header)
    if reply_to:
        reply_domain = extract_sender_domain(reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            result["spoofed"] = True
            result["reason"] = f"From domain ({from_domain}) ≠ Reply-To domain ({reply_domain})"
    # Check if display name contains a legitimate brand but domain doesn't match
    display_name = re.sub(r'<.*?>', '', from_header).strip().lower()
    for legit in LEGITIMATE_DOMAINS:
        brand = legit.split(".")[0]
        if brand in display_name and from_domain and brand not in from_domain:
            result["spoofed"] = True
            result["reason"] = f'Display name contains "{brand}" but domain is "{from_domain}"'
            break
    return result


def count_keyword_hits(text: str, keywords: list[str]) -> tuple[int, list[str]]:
    """Count keyword matches and return matched words."""
    text_lower = text.lower()
    matched = [kw for kw in keywords if kw in text_lower]
    return len(matched), matched


def calculate_text_entropy(text: str) -> float:
    """Measure randomness – very high = possible encoded payload."""
    import math
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def detect_html_tricks(html: str) -> list[str]:
    """Detect HTML obfuscation tricks."""
    tricks = []
    if re.search(r'style=["\'].*?display\s*:\s*none', html, re.IGNORECASE):
        tricks.append("Hidden elements (display:none)")
    if re.search(r'font-size\s*:\s*[01]px', html, re.IGNORECASE):
        tricks.append("Invisible text (font-size: 0-1px)")
    if html.count('<a ') > 10:
        tricks.append(f"Excessive links ({html.count('<a ')} anchor tags)")
    if re.search(r'&#x[0-9a-fA-F]+;|&#\d+;', html):
        tricks.append("HTML entity encoding (possible obfuscation)")
    return tricks

# ── History log ───────────────────────────────────────────────────────────────

def load_history() -> list[dict]:
    if not LOG_FILE.exists():
        return []
    try:
        with open(LOG_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def save_to_history(entry: dict) -> None:
    history = load_history()
    history.insert(0, entry)
    history = history[:200]          # keep last 200
    with open(LOG_FILE, "w") as f:
        json.dump(history, f, indent=2, default=str)


def make_scan_id(subject: str, sender: str) -> str:
    raw = f"{subject}{sender}{datetime.datetime.now().isoformat()}"
    return hashlib.md5(raw.encode()).hexdigest()[:10].upper()


def now_str() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def risk_label(score: float) -> str:
    if score >= 70:
        return "PHISHING"
    if score >= 35:
        return "SUSPICIOUS"
    return "SAFE"


def risk_color(label: str) -> str:
    return {"PHISHING": "#e63946", "SUSPICIOUS": "#f4a261", "SAFE": "#2a9d8f"}.get(label, "#888")


def truncate(text: str, n: int = 80) -> str:
    return text[:n] + "…" if len(text) > n else text

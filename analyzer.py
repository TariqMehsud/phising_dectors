"""
analyzer.py - Rule-based + URL analysis engine for Phishing Email Detector

Combines:
  1. Rule-based heuristics (keywords, sender checks, HTML tricks)
  2. URL scanning (VirusTotal API or local simulation)
  3. ML model prediction
  4. Optional LLM analysis via Claude/OpenAI API
"""

import re
import os
import time
import json
import email
import hashlib
import requests
import datetime
from email import policy
from bs4 import BeautifulSoup
from dataclasses import dataclass, field, asdict
from typing import Optional

from utils import (
    URGENT_KEYWORDS, FINANCIAL_KEYWORDS, CREDENTIAL_KEYWORDS, THREAT_KEYWORDS,
    KNOWN_PHISHING_DOMAINS, LEGITIMATE_DOMAINS,
    extract_urls, extract_domain, is_ip_url, has_url_shortener,
    check_url_mismatch, count_subdomains, url_has_at_symbol,
    calculate_url_entropy, extract_sender_domain, check_sender_spoofing,
    count_keyword_hits, detect_html_tricks, now_str, make_scan_id,
    risk_label, save_to_history,
)
from model import predict_email

# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class URLScanResult:
    url:            str
    domain:         str
    is_ip_url:      bool = False
    is_shortener:   bool = False
    known_phishing: bool = False
    has_at:         bool = False
    subdomain_count: int = 0
    entropy:        float = 0.0
    vt_detections:  int = -1    # -1 = not checked
    risk_score:     float = 0.0
    flags:          list = field(default_factory=list)


@dataclass
class AnalysisResult:
    scan_id:         str   = ""
    timestamp:       str   = ""
    # Email metadata
    subject:         str   = ""
    sender:          str   = ""
    reply_to:        str   = ""
    recipient:       str   = ""
    # Scores
    risk_score:      float = 0.0
    ml_score:        float = 0.0
    rule_score:      float = 0.0
    label:           str   = "SAFE"
    # Flags
    flags:           list  = field(default_factory=list)
    url_results:     list  = field(default_factory=list)
    keyword_hits:    dict  = field(default_factory=dict)
    html_tricks:     list  = field(default_factory=list)
    sender_spoofed:  bool  = False
    spoof_reason:    str   = ""
    # LLM
    llm_analysis:    str   = ""
    llm_used:        bool  = False
    # Body snippet
    body_snippet:    str   = ""
    full_body:       str   = ""
    raw_urls:        list  = field(default_factory=list)

# ── Email parsing ─────────────────────────────────────────────────────────────

def parse_email_text(raw: str) -> dict:
    """
    Parse raw email text (RFC 2822 format) or plain text.
    Returns dict with subject, from, reply_to, to, body (plain), html.
    """
    result = {"subject": "", "from": "", "reply_to": "", "to": "", "body": "", "html": ""}
    try:
        msg = email.message_from_string(raw, policy=policy.default)
        result["subject"]   = str(msg.get("Subject", ""))
        result["from"]      = str(msg.get("From", ""))
        result["reply_to"]  = str(msg.get("Reply-To", ""))
        result["to"]        = str(msg.get("To", ""))
        # Extract body parts
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    result["body"] += part.get_content() or ""
                elif ct == "text/html":
                    result["html"] += part.get_content() or ""
        else:
            ct = msg.get_content_type()
            content = msg.get_content() or ""
            if ct == "text/html":
                result["html"] = content
                result["body"] = BeautifulSoup(content, "lxml").get_text(" ")
            else:
                result["body"] = content
    except Exception:
        # Fallback: treat entire input as plain text
        result["body"] = raw
    # If we only have HTML, extract text from it
    if result["html"] and not result["body"]:
        result["body"] = BeautifulSoup(result["html"], "lxml").get_text(" ")
    return result


def parse_pasted_text(text: str) -> dict:
    """
    Handle plain pasted email text (no MIME headers).
    Try to extract common header-like lines (Subject:, From:, To:).
    """
    result = {"subject": "", "from": "", "reply_to": "", "to": "", "body": text, "html": ""}
    lines = text.splitlines()
    body_start = 0
    for i, line in enumerate(lines):
        lower = line.lower()
        if lower.startswith("subject:"):
            result["subject"] = line.split(":", 1)[1].strip()
            body_start = i + 1
        elif lower.startswith("from:"):
            result["from"] = line.split(":", 1)[1].strip()
            body_start = i + 1
        elif lower.startswith("to:"):
            result["to"] = line.split(":", 1)[1].strip()
            body_start = i + 1
        elif lower.startswith("reply-to:"):
            result["reply_to"] = line.split(":", 1)[1].strip()
            body_start = i + 1
        elif i > 10:
            break
    result["body"] = "\n".join(lines[body_start:]).strip() or text
    return result

# ── URL scanning ──────────────────────────────────────────────────────────────

def scan_url(url: str, vt_api_key: str = "") -> URLScanResult:
    """Analyze a single URL for phishing indicators."""
    domain = extract_domain(url)
    res = URLScanResult(url=url[:200], domain=domain)

    # Local heuristic checks
    if is_ip_url(url):
        res.is_ip_url = True
        res.flags.append("Uses IP address instead of domain name")
        res.risk_score += 30

    if has_url_shortener(url):
        res.is_shortener = True
        res.flags.append("URL shortener detected (hides destination)")
        res.risk_score += 20

    if domain in KNOWN_PHISHING_DOMAINS:
        res.known_phishing = True
        res.flags.append(f"Domain '{domain}' is in known phishing list")
        res.risk_score += 50

    if url_has_at_symbol(url):
        res.has_at = True
        res.flags.append("URL contains '@' symbol (parser trick)")
        res.risk_score += 25

    subs = count_subdomains(url)
    res.subdomain_count = subs
    if subs >= 3:
        res.flags.append(f"Excessive subdomains ({subs}) to mimic legitimate sites")
        res.risk_score += 15 * (subs - 2)

    entropy = calculate_url_entropy(url)
    res.entropy = entropy
    if entropy > 4.5:
        res.flags.append(f"High URL entropy ({entropy:.2f}) – possible obfuscation")
        res.risk_score += 15

    # Check lookalike domains
    for legit in LEGITIMATE_DOMAINS:
        brand = legit.split(".")[0]
        if brand in domain and legit != domain:
            res.flags.append(f"Lookalike domain: '{domain}' impersonates '{legit}'")
            res.risk_score += 40
            break

    # VirusTotal API (optional)
    if vt_api_key:
        vt_result = check_virustotal(url, vt_api_key)
        res.vt_detections = vt_result.get("detections", -1)
        if res.vt_detections > 0:
            res.flags.append(f"VirusTotal: {res.vt_detections} engine(s) flagged this URL")
            res.risk_score += min(res.vt_detections * 5, 40)

    res.risk_score = min(res.risk_score, 100)
    return res


def check_virustotal(url: str, api_key: str) -> dict:
    """Query VirusTotal URL scan API."""
    try:
        headers = {"x-apikey": api_key}
        # Submit URL
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10,
        )
        if resp.status_code != 200:
            return {}
        analysis_id = resp.json()["data"]["id"]
        time.sleep(2)
        # Get results
        r2 = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10,
        )
        if r2.status_code != 200:
            return {}
        stats = r2.json()["data"]["attributes"]["stats"]
        return {"detections": stats.get("malicious", 0) + stats.get("suspicious", 0)}
    except Exception:
        return {}

# ── Rule-based scoring ────────────────────────────────────────────────────────

def rule_based_score(parsed: dict) -> tuple[float, list, dict, list]:
    """
    Compute rule-based risk contribution.
    Returns (score 0-100, flags, keyword_hits, html_tricks).
    """
    score  = 0.0
    flags  = []
    kw_hits = {}

    full_text = f"{parsed['subject']} {parsed['body']}".lower()

    # 1. Keyword analysis
    for group_name, keywords, weight in [
        ("Urgency",     URGENT_KEYWORDS,     3),
        ("Financial",   FINANCIAL_KEYWORDS,  2),
        ("Credential",  CREDENTIAL_KEYWORDS, 4),
        ("Threat",      THREAT_KEYWORDS,     3),
    ]:
        cnt, matched = count_keyword_hits(full_text, keywords)
        if matched:
            kw_hits[group_name] = matched
            contribution = min(cnt * weight, 20)
            score += contribution
            flags.append(f"{group_name} keywords ({cnt}): {', '.join(matched[:4])}")

    # 2. Excessive exclamation marks
    excl = full_text.count("!")
    if excl > 3:
        score += min(excl * 2, 10)
        flags.append(f"Excessive exclamation marks ({excl})")

    # 3. ALL CAPS subject
    subj = parsed.get("subject", "")
    if subj and sum(1 for c in subj if c.isupper()) / max(len(subj), 1) > 0.5:
        score += 8
        flags.append("Subject line is mostly uppercase")

    # 4. Suspicious subject patterns
    suspicious_subjects = [
        r"urgent", r"action required", r"verify", r"suspended",
        r"winner", r"prize", r"claim", r"password",
    ]
    for pat in suspicious_subjects:
        if re.search(pat, subj, re.IGNORECASE):
            score += 5
            break

    # 5. Sender spoofing
    spoof = check_sender_spoofing(parsed.get("from", ""), parsed.get("reply_to", ""))
    if spoof["spoofed"]:
        score += 25
        flags.append(f"Sender spoofing: {spoof['reason']}")

    # 6. HTML tricks
    html_tricks = []
    if parsed.get("html"):
        html_tricks = detect_html_tricks(parsed["html"])
        for trick in html_tricks:
            score += 10
            flags.append(f"HTML obfuscation: {trick}")

    # 7. Generic greeting (no name)
    body_lower = parsed.get("body", "").lower()
    for generic in ["dear customer", "dear user", "dear account holder",
                    "dear valued", "dear member"]:
        if generic in body_lower:
            score += 5
            flags.append(f"Generic greeting: '{generic}'")
            break

    # 8. Requests for sensitive info
    sensitive_patterns = [
        r"social security", r"ssn", r"credit card number",
        r"bank account", r"routing number", r"mother.{0,10}maiden",
    ]
    for pat in sensitive_patterns:
        if re.search(pat, body_lower):
            score += 15
            flags.append("Requests sensitive personal/financial information")
            break

    return min(score, 100), flags, kw_hits, html_tricks

# ── Main analysis orchestrator ────────────────────────────────────────────────

def analyze_email(
    raw_email_text: str,
    vt_api_key:     str = "",
    llm_api_key:    str = "",
    llm_provider:   str = "anthropic",
) -> AnalysisResult:
    """
    Full pipeline: parse → rule-based → ML → URL scan → (LLM) → combine scores.
    """
    # 1. Parse
    if re.match(r'^(From|Subject|To|Date|MIME):', raw_email_text, re.IGNORECASE | re.MULTILINE):
        parsed = parse_email_text(raw_email_text)
    else:
        parsed = parse_pasted_text(raw_email_text)

    subject  = parsed.get("subject", "")
    sender   = parsed.get("from", "")
    reply_to = parsed.get("reply_to", "")
    body     = parsed.get("body", "")

    result = AnalysisResult(
        scan_id     = make_scan_id(subject, sender),
        timestamp   = now_str(),
        subject     = subject or "(No Subject)",
        sender      = sender or "(Unknown Sender)",
        reply_to    = reply_to,
        body_snippet= body[:500].replace("\n", " "),
        full_body   = body,
    )

    # 2. Rule-based scoring
    rule_score, r_flags, kw_hits, html_tricks = rule_based_score(parsed)
    result.rule_score  = rule_score
    result.flags       = r_flags
    result.keyword_hits= kw_hits
    result.html_tricks = html_tricks

    spoof = check_sender_spoofing(sender, reply_to)
    result.sender_spoofed = spoof["spoofed"]
    result.spoof_reason   = spoof["reason"]

    # 3. URL scanning
    all_text = f"{subject} {body} {parsed.get('html','')}"
    urls = extract_urls(all_text)
    result.raw_urls = urls[:20]
    url_results = []
    url_risk_sum = 0.0

    for url in urls[:10]:   # scan first 10 URLs max
        ur = scan_url(url, vt_api_key)
        url_results.append(asdict(ur))
        url_risk_sum += ur.risk_score
        for flag in ur.flags:
            combined = f"[URL] {flag}"
            if combined not in result.flags:
                result.flags.append(combined)

    result.url_results = url_results
    url_avg = url_risk_sum / max(len(url_results), 1) if url_results else 0

    # 4. ML prediction
    ml_pred = predict_email(subject, body, sender)
    result.ml_score = ml_pred.get("ml_score", 50.0)

    # 5. LLM analysis (optional)
    if llm_api_key:
        llm_text = _llm_analyze(subject, body, sender, llm_api_key, llm_provider)
        result.llm_analysis = llm_text
        result.llm_used     = True

    # 6. Combined weighted score
    # Weights: ML 40%, Rules 35%, URL 25%
    combined = (
        result.ml_score   * 0.40 +
        result.rule_score * 0.35 +
        url_avg           * 0.25
    )
    # Boost if sender spoofed
    if result.sender_spoofed:
        combined = min(combined + 15, 100)
    # Boost if LLM flagged it
    if result.llm_used and "phishing" in result.llm_analysis.lower():
        combined = min(combined + 10, 100)

    result.risk_score = round(combined, 1)
    result.label      = risk_label(result.risk_score)

    # 7. Save to history
    save_to_history({
        "scan_id":    result.scan_id,
        "timestamp":  result.timestamp,
        "subject":    result.subject[:80],
        "sender":     result.sender[:80],
        "risk_score": result.risk_score,
        "label":      result.label,
        "n_urls":     len(urls),
    })

    return result

# ── Optional LLM analysis ─────────────────────────────────────────────────────

def _llm_analyze(subject: str, body: str, sender: str,
                 api_key: str, provider: str = "anthropic") -> str:
    """Call LLM for semantic phishing analysis."""
    prompt = f"""You are a cybersecurity expert specializing in phishing detection.
Analyze this email and provide a concise assessment (3-5 sentences):

Subject: {subject}
From: {sender}
Body: {body[:1500]}

Evaluate: Is this a phishing attempt? What are the key red flags or why it appears legitimate?
Start with 'PHISHING DETECTED:' or 'APPEARS LEGITIMATE:' then explain your reasoning."""

    try:
        if provider == "anthropic":
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-opus-4-5",
                    "max_tokens": 400,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json()["content"][0]["text"]
        elif provider == "openai":
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 400,
                },
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"LLM analysis unavailable: {e}"

    return "LLM analysis unavailable."

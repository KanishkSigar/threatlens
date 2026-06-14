"""
Email Analyzer Service
Analyzes email content, headers, and embedded links for phishing indicators.
"""

import re
from typing import Optional
from urllib.parse import urlparse

from app.services.url_analyzer import extract_url_features, SUSPICIOUS_KEYWORDS


# Email-specific phishing indicators
URGENCY_KEYWORDS = [
    "urgent", "immediately", "asap", "right away", "within 24 hours",
    "within 48 hours", "expire", "suspended", "terminated", "locked",
    "unauthorized", "unusual activity", "verify now", "act now",
    "limited time", "final warning", "last chance", "deadline",
]

SOCIAL_ENGINEERING_PHRASES = [
    "click here", "click below", "click the link",
    "verify your account", "confirm your identity",
    "update your information", "reset your password",
    "unusual sign-in", "suspicious activity",
    "we noticed", "your account has been",
    "failure to verify", "will result in",
    "dear customer", "dear user", "valued customer",
]


def analyze_email_content(
    email_content: str,
    subject: Optional[str] = None,
    sender: Optional[str] = None,
) -> dict:
    """
    Analyze email content for phishing indicators.
    Returns a dictionary of features and risk indicators.
    """
    content_lower = email_content.lower()
    subject_lower = (subject or "").lower()

    features = {
        # Content length
        "content_length": len(email_content),
        "subject_length": len(subject or ""),

        # Urgency indicators
        "urgency_keyword_count": sum(
            1 for kw in URGENCY_KEYWORDS if kw in content_lower
        ),
        "has_urgency": any(kw in content_lower for kw in URGENCY_KEYWORDS),

        # Social engineering phrases
        "social_engineering_count": sum(
            1 for phrase in SOCIAL_ENGINEERING_PHRASES if phrase in content_lower
        ),
        "has_social_engineering": any(
            phrase in content_lower for phrase in SOCIAL_ENGINEERING_PHRASES
        ),

        # Suspicious keywords
        "suspicious_keyword_count": sum(
            1 for kw in SUSPICIOUS_KEYWORDS if kw in content_lower
        ),

        # Links analysis
        "urls_found": [],
        "url_count": 0,
        "has_mismatched_urls": False,
        "has_ip_urls": False,
        "has_shortened_urls": False,

        # Sender analysis
        "sender_email": sender,
        "sender_domain": None,
        "is_freemail_sender": False,

        # Subject analysis
        "subject_has_urgency": any(kw in subject_lower for kw in URGENCY_KEYWORDS),
        "subject_has_re_fw": bool(re.match(r"^(re|fw|fwd):", subject_lower)) if subject else False,

        # Content patterns
        "has_html": bool(re.search(r"<[a-z][\s\S]*>", content_lower)),
        "has_form": "<form" in content_lower,
        "has_hidden_text": "display:none" in content_lower or "visibility:hidden" in content_lower,
        "exclamation_count": email_content.count("!"),
        "capitalized_word_ratio": _capitalized_ratio(email_content),

        # Grammar indicators
        "has_spelling_errors_indicators": _check_common_phishing_misspellings(content_lower),
    }

    # Extract and analyze URLs
    urls = _extract_urls(email_content)
    features["urls_found"] = urls
    features["url_count"] = len(urls)

    # Check for IP-based URLs
    features["has_ip_urls"] = any(
        _is_ip_url(url) for url in urls
    )

    # Analyze sender
    if sender:
        sender_match = re.search(r"@([\w.-]+)", sender)
        if sender_match:
            sender_domain = sender_match.group(1).lower()
            features["sender_domain"] = sender_domain
            features["is_freemail_sender"] = sender_domain in [
                "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                "aol.com", "mail.com", "protonmail.com",
            ]

    return features


def calculate_email_risk_score(features: dict) -> float:
    """
    Calculate a risk score (0-100) based on email features.
    Uses a weighted scoring system.
    """
    score = 0.0

    # Urgency (max 20 points)
    score += min(features.get("urgency_keyword_count", 0) * 5, 20)

    # Social engineering (max 25 points)
    score += min(features.get("social_engineering_count", 0) * 7, 25)

    # Suspicious keywords (max 15 points)
    score += min(features.get("suspicious_keyword_count", 0) * 3, 15)

    # URL indicators (max 20 points)
    if features.get("has_ip_urls"):
        score += 10
    if features.get("url_count", 0) > 5:
        score += 5
    if features.get("has_shortened_urls"):
        score += 5

    # Content patterns (max 15 points)
    if features.get("has_form"):
        score += 8
    if features.get("has_hidden_text"):
        score += 7

    # Sender (max 5 points)
    if features.get("is_freemail_sender"):
        score += 3

    # Subject urgency (bonus)
    if features.get("subject_has_urgency"):
        score += 5

    return min(score, 100.0)


def _extract_urls(text: str) -> list[str]:
    """Extract all URLs from text content."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


def _is_ip_url(url: str) -> bool:
    """Check if a URL uses an IP address."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))


def _capitalized_ratio(text: str) -> float:
    """Calculate the ratio of fully capitalized words."""
    words = text.split()
    if not words:
        return 0.0
    capitalized = sum(1 for w in words if w.isupper() and len(w) > 1)
    return round(capitalized / len(words), 4)


def _check_common_phishing_misspellings(text: str) -> bool:
    """Check for common misspellings/variations used in phishing."""
    indicators = [
        "paypa1", "amaz0n", "g00gle", "micros0ft", "app1e",
        "netfl1x", "faceb00k", "1nstagram", "verif1cation",
    ]
    return any(indicator in text for indicator in indicators)

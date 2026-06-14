"""
URL Analyzer Service
Extracts 30+ features from a URL for phishing detection.
This is the core analysis engine of ThreatLens.
"""

import re
import math
import socket
from urllib.parse import urlparse, parse_qs
from typing import Optional
from collections import Counter

import tldextract
import httpx

from app.services.whois_service import get_domain_age_days
from app.services.ssl_checker import check_ssl_certificate
from app.services.dns_analyzer import analyze_dns


# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "update", "secure", "account", "banking", "confirm",
    "password", "credential", "authenticate", "wallet",
    "paypal", "apple", "microsoft", "google", "amazon",
    "netflix", "facebook", "instagram", "support", "help",
    "suspend", "restrict", "unlock", "expire", "urgent",
]

# Known phishing TLDs (commonly abused)
SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club",
    "work", "buzz", "surf", "icu", "cam", "monster",
    "rest", "fit", "beauty", "hair", "quest",
]

# Legitimate shortener domains
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string — higher = more random/suspicious."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def has_ip_address(url: str) -> bool:
    """Check if URL uses a raw IP address instead of a domain."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # IPv4 pattern
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    # IPv6 pattern (simplified)
    if re.match(ipv4_pattern, hostname):
        return True
    if hostname.startswith("[") and hostname.endswith("]"):
        return True
    return False


def count_special_chars(url: str) -> dict:
    """Count special characters in a URL."""
    return {
        "dots": url.count("."),
        "hyphens": url.count("-"),
        "underscores": url.count("_"),
        "slashes": url.count("/"),
        "question_marks": url.count("?"),
        "equals": url.count("="),
        "at_signs": url.count("@"),
        "ampersands": url.count("&"),
        "tildes": url.count("~"),
        "percent": url.count("%"),
    }


def extract_url_features(url: str) -> dict:
    """
    Extract all features from a URL for ML prediction.
    Returns a dictionary of feature name -> value.
    """
    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    special_chars = count_special_chars(url)

    # ─── URL-Based Features ─────────────────────────────────
    features = {
        # Length features
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),

        # Structural features
        "num_dots": special_chars["dots"],
        "num_hyphens": special_chars["hyphens"],
        "num_underscores": special_chars["underscores"],
        "num_slashes": special_chars["slashes"],
        "num_query_params": len(parse_qs(query)),
        "num_at_signs": special_chars["at_signs"],
        "num_ampersands": special_chars["ampersands"],
        "num_percent": special_chars["percent"],
        "path_depth": len([p for p in path.split("/") if p]),

        # Boolean flags
        "has_ip_address": has_ip_address(url),
        "is_https": parsed.scheme == "https",
        "has_port": parsed.port is not None and parsed.port not in (80, 443),
        "has_at_sign": "@" in url,
        "has_double_slash_redirect": "//" in path,
        "has_hex_encoding": "%" in url,

        # Domain features
        "subdomain_count": len(extracted.subdomain.split(".")) if extracted.subdomain else 0,
        "domain": extracted.domain,
        "tld": extracted.suffix,
        "is_suspicious_tld": extracted.suffix.lower() in SUSPICIOUS_TLDS,
        "is_shortener": hostname.lower() in URL_SHORTENERS,

        # Entropy (randomness)
        "url_entropy": calculate_entropy(url),
        "domain_entropy": calculate_entropy(hostname),

        # Keyword features
        "suspicious_keyword_count": sum(
            1 for kw in SUSPICIOUS_KEYWORDS
            if kw in url.lower()
        ),
        "has_suspicious_keywords": any(
            kw in url.lower() for kw in SUSPICIOUS_KEYWORDS
        ),
    }

    return features


async def enrich_features_with_external_data(url: str, features: dict) -> dict:
    """
    Enrich the basic URL features with data from external services.
    These are slower lookups (WHOIS, SSL, DNS) so they run async.
    """
    parsed = urlparse(url if url.startswith("http") else f"http://{url}")
    hostname = parsed.hostname or ""

    # Domain age via WHOIS
    domain_age = await get_domain_age_days(hostname)
    features["domain_age_days"] = domain_age
    features["is_new_domain"] = domain_age is not None and domain_age < 30

    # SSL certificate check
    ssl_info = await check_ssl_certificate(hostname)
    features["ssl_valid"] = ssl_info.get("valid", False)
    features["ssl_issuer"] = ssl_info.get("issuer", "unknown")
    features["ssl_days_remaining"] = ssl_info.get("days_remaining", -1)

    # DNS analysis
    dns_info = await analyze_dns(hostname)
    features["has_dns_record"] = dns_info.get("has_record", False)
    features["dns_record_count"] = dns_info.get("record_count", 0)

    return features


def get_numeric_features(features: dict) -> list[float]:
    """
    Convert feature dictionary to a numeric vector for ML model input.
    Returns features in a consistent order for the trained model.
    """
    numeric_keys = [
        "url_length", "hostname_length", "path_length", "query_length",
        "num_dots", "num_hyphens", "num_underscores", "num_slashes",
        "num_query_params", "num_at_signs", "num_ampersands", "num_percent",
        "path_depth",
        "has_ip_address", "is_https", "has_port", "has_at_sign",
        "has_double_slash_redirect", "has_hex_encoding",
        "subdomain_count", "is_suspicious_tld", "is_shortener",
        "url_entropy", "domain_entropy",
        "suspicious_keyword_count", "has_suspicious_keywords",
        "domain_age_days", "is_new_domain",
        "ssl_valid", "ssl_days_remaining",
        "has_dns_record", "dns_record_count",
    ]

    vector = []
    for key in numeric_keys:
        value = features.get(key)
        if isinstance(value, bool):
            vector.append(1.0 if value else 0.0)
        elif isinstance(value, (int, float)):
            vector.append(float(value))
        elif value is None:
            vector.append(-1.0)  # Missing value marker
        else:
            vector.append(0.0)

    return vector


# Feature names in the same order as get_numeric_features for model training
FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_query_params", "num_at_signs", "num_ampersands", "num_percent",
    "path_depth",
    "has_ip_address", "is_https", "has_port", "has_at_sign",
    "has_double_slash_redirect", "has_hex_encoding",
    "subdomain_count", "is_suspicious_tld", "is_shortener",
    "url_entropy", "domain_entropy",
    "suspicious_keyword_count", "has_suspicious_keywords",
    "domain_age_days", "is_new_domain",
    "ssl_valid", "ssl_days_remaining",
    "has_dns_record", "dns_record_count",
]

"""
Helper Utilities
Common utility functions used across the application.
"""

from typing import Optional


def classify_risk_level(risk_score: float) -> str:
    """Classify a risk score into a human-readable risk level."""
    if risk_score >= 80:
        return "CRITICAL"
    elif risk_score >= 60:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def classify_verdict(risk_score: float) -> str:
    """Determine the verdict based on risk score."""
    if risk_score >= 70:
        return "PHISHING"
    elif risk_score >= 40:
        return "SUSPICIOUS"
    else:
        return "SAFE"


def generate_recommendations(verdict: str, features: dict) -> list[str]:
    """Generate actionable recommendations based on scan results."""
    recommendations = []

    if verdict == "PHISHING":
        recommendations.append("⚠️ Do NOT enter any credentials or personal information on this site")
        recommendations.append("🚫 Do not click any links or download files from this source")
        recommendations.append("📢 Report this URL to your IT security team or phishing reporting service")
    elif verdict == "SUSPICIOUS":
        recommendations.append("⚠️ Exercise caution — this source shows suspicious characteristics")
        recommendations.append("🔍 Verify the sender/domain through an independent channel before proceeding")
        recommendations.append("🔒 Do not enter sensitive information until verified")
    else:
        recommendations.append("✅ This appears to be a legitimate source")
        recommendations.append("🔒 Always verify the URL in your browser address bar before entering credentials")

    # Feature-specific recommendations
    if features.get("has_ip_address"):
        recommendations.append("🔴 URL uses a raw IP address instead of a domain name — this is a strong phishing indicator")

    if features.get("is_https") is False:
        recommendations.append("🔴 Connection is not encrypted (no HTTPS) — never enter passwords on HTTP sites")

    if features.get("domain_age_days") is not None and features["domain_age_days"] < 30:
        recommendations.append(f"🟡 Domain is only {features['domain_age_days']} days old — newly created domains are often used for phishing")

    if features.get("has_suspicious_keywords"):
        recommendations.append("🟡 URL contains suspicious keywords commonly used in phishing attacks")

    return recommendations


def truncate_url(url: str, max_length: int = 100) -> str:
    """Truncate a URL for display purposes."""
    if len(url) <= max_length:
        return url
    return url[:max_length - 3] + "..."

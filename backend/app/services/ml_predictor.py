"""
ML Predictor Service
Loads the trained XGBoost model and makes phishing predictions.
Falls back to a heuristic rule-based system if no model is available.
"""

import os
import logging
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# Global model cache
_model = None
_model_loaded = False


def _get_model_path() -> str:
    """Get the path to the trained model file."""
    return os.path.join(os.path.dirname(__file__), "..", "ml", "model.pkl")


def load_model():
    """Load the trained ML model from disk."""
    global _model, _model_loaded

    model_path = _get_model_path()

    if os.path.exists(model_path):
        try:
            import joblib
            _model = joblib.load(model_path)
            _model_loaded = True
            logger.info("ML model loaded successfully from %s", model_path)
        except Exception as e:
            logger.warning("Failed to load ML model: %s. Using heuristic fallback.", e)
            _model = None
            _model_loaded = False
    else:
        logger.info("No trained model found at %s. Using heuristic fallback.", model_path)
        _model_loaded = False


def predict_phishing(feature_vector: list[float]) -> dict:
    """
    Predict whether a URL is phishing based on its feature vector.

    Returns:
        dict with 'risk_score' (0-100), 'confidence' (0-1), and 'verdict'
    """
    global _model, _model_loaded

    if _model_loaded and _model is not None:
        return _predict_with_model(feature_vector)
    else:
        return _predict_heuristic(feature_vector)


def _predict_with_model(feature_vector: list[float]) -> dict:
    """Make prediction using the trained XGBoost model."""
    try:
        features_array = np.array([feature_vector])

        # Get probability prediction
        probabilities = _model.predict_proba(features_array)[0]
        phishing_prob = float(probabilities[1])  # Probability of being phishing

        risk_score = round(phishing_prob * 100, 1)
        confidence = round(max(probabilities), 4)

        if risk_score >= 70:
            verdict = "PHISHING"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return {
            "risk_score": risk_score,
            "confidence": confidence,
            "verdict": verdict,
            "method": "ml_model",
        }

    except Exception as e:
        logger.error("ML prediction failed: %s. Falling back to heuristic.", e)
        return _predict_heuristic(feature_vector)


def _predict_heuristic(feature_vector: list[float]) -> dict:
    """
    Rule-based heuristic prediction as a fallback when no ML model is available.
    Uses weighted scoring based on feature positions.

    Feature order (matching url_analyzer.FEATURE_NAMES):
    0: url_length, 1: hostname_length, 2: path_length, 3: query_length,
    4: num_dots, 5: num_hyphens, 6: num_underscores, 7: num_slashes,
    8: num_query_params, 9: num_at_signs, 10: num_ampersands, 11: num_percent,
    12: path_depth,
    13: has_ip_address, 14: is_https, 15: has_port, 16: has_at_sign,
    17: has_double_slash_redirect, 18: has_hex_encoding,
    19: subdomain_count, 20: is_suspicious_tld, 21: is_shortener,
    22: url_entropy, 23: domain_entropy,
    24: suspicious_keyword_count, 25: has_suspicious_keywords,
    26: domain_age_days, 27: is_new_domain,
    28: ssl_valid, 29: ssl_days_remaining,
    30: has_dns_record, 31: dns_record_count,
    """
    score = 0.0
    v = feature_vector

    # URL length (long URLs are suspicious)
    if len(v) > 0 and v[0] > 75:
        score += 8
    if len(v) > 0 and v[0] > 150:
        score += 7

    # Has IP address (strong phishing indicator)
    if len(v) > 13 and v[13] > 0:
        score += 20

    # No HTTPS
    if len(v) > 14 and v[14] == 0:
        score += 10

    # Has port number
    if len(v) > 15 and v[15] > 0:
        score += 8

    # Has @ sign in URL
    if len(v) > 16 and v[16] > 0:
        score += 15

    # Double slash redirect
    if len(v) > 17 and v[17] > 0:
        score += 8

    # Many subdomains
    if len(v) > 19 and v[19] > 2:
        score += 10

    # Suspicious TLD
    if len(v) > 20 and v[20] > 0:
        score += 12

    # Suspicious keywords
    if len(v) > 24 and v[24] > 0:
        score += min(v[24] * 5, 15)

    # New domain (< 30 days)
    if len(v) > 27 and v[27] > 0:
        score += 12

    # Invalid SSL
    if len(v) > 28 and v[28] == 0:
        score += 8

    # No DNS record
    if len(v) > 30 and v[30] == 0:
        score += 10

    # High entropy
    if len(v) > 22 and v[22] > 4.5:
        score += 5

    # Many hyphens
    if len(v) > 5 and v[5] > 3:
        score += 5

    # Cap at 100
    risk_score = min(round(score, 1), 100.0)

    # Confidence is lower for heuristic
    confidence = 0.65

    if risk_score >= 70:
        verdict = "PHISHING"
    elif risk_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "risk_score": risk_score,
        "confidence": confidence,
        "verdict": verdict,
        "method": "heuristic",
    }

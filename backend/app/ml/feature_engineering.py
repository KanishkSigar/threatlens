"""
Feature Engineering Module
Handles feature extraction and preprocessing for ML model training.
"""

import pandas as pd
import numpy as np
from typing import Optional

from app.services.url_analyzer import (
    extract_url_features,
    FEATURE_NAMES,
    calculate_entropy,
    has_ip_address,
    count_special_chars,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)


def extract_features_for_training(url: str) -> dict:
    """
    Extract features from a URL for model training.
    This is the offline version that doesn't call external APIs
    (WHOIS, SSL, DNS) since those would be too slow for batch processing.
    """
    features = extract_url_features(url)

    # Set external features to defaults for training
    features["domain_age_days"] = -1
    features["is_new_domain"] = False
    features["ssl_valid"] = False
    features["ssl_days_remaining"] = -1
    features["has_dns_record"] = True
    features["dns_record_count"] = 1

    return features


def features_to_vector(features: dict) -> list[float]:
    """Convert a feature dictionary to a numeric vector matching FEATURE_NAMES order."""
    vector = []
    for name in FEATURE_NAMES:
        value = features.get(name)
        if isinstance(value, bool):
            vector.append(1.0 if value else 0.0)
        elif isinstance(value, (int, float)):
            vector.append(float(value))
        elif value is None:
            vector.append(-1.0)
        else:
            vector.append(0.0)
    return vector


def prepare_dataset(urls: list[str], labels: list[int]) -> tuple[np.ndarray, np.ndarray]:
    """
    Prepare a dataset from a list of URLs and their labels.

    Args:
        urls: List of URLs to extract features from.
        labels: List of labels (0 = legitimate, 1 = phishing).

    Returns:
        Tuple of (feature_matrix, labels_array)
    """
    feature_vectors = []

    for url in urls:
        try:
            features = extract_features_for_training(url)
            vector = features_to_vector(features)
            feature_vectors.append(vector)
        except Exception:
            # Use zero vector for failed extractions
            feature_vectors.append([0.0] * len(FEATURE_NAMES))

    X = np.array(feature_vectors)
    y = np.array(labels)

    return X, y

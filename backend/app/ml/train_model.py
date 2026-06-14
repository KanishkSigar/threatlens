"""
Model Training Script
Trains an XGBoost classifier on phishing URL datasets.

Usage:
    python -m app.ml.train_model
    python -m app.ml.train_model --evaluate
"""

import os
import sys
import argparse
import logging

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score,
)
from xgboost import XGBClassifier

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.ml.feature_engineering import extract_features_for_training, features_to_vector
from app.services.url_analyzer import FEATURE_NAMES

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
DATASET_DIR = os.path.join(MODEL_DIR, "datasets")


def generate_synthetic_dataset(n_samples: int = 2000) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate a synthetic training dataset for initial model bootstrapping.
    This creates realistic feature vectors for phishing and legitimate URLs.
    In production, replace with real datasets (PhishTank, UCI, etc.)
    """
    logger.info("Generating synthetic dataset with %d samples...", n_samples)
    rng = np.random.RandomState(42)

    n_legit = n_samples // 2
    n_phish = n_samples - n_legit

    features_list = []
    labels = []

    # ─── Generate Legitimate URL Features ──────────────────
    for _ in range(n_legit):
        features = {
            "url_length": rng.randint(15, 60),
            "hostname_length": rng.randint(8, 25),
            "path_length": rng.randint(0, 30),
            "query_length": rng.randint(0, 20),
            "num_dots": rng.randint(1, 3),
            "num_hyphens": rng.randint(0, 1),
            "num_underscores": 0,
            "num_slashes": rng.randint(1, 4),
            "num_query_params": rng.randint(0, 2),
            "num_at_signs": 0,
            "num_ampersands": rng.randint(0, 1),
            "num_percent": 0,
            "path_depth": rng.randint(0, 3),
            "has_ip_address": False,
            "is_https": rng.random() > 0.1,  # 90% HTTPS
            "has_port": False,
            "has_at_sign": False,
            "has_double_slash_redirect": False,
            "has_hex_encoding": rng.random() > 0.9,
            "subdomain_count": rng.choice([0, 1], p=[0.6, 0.4]),
            "is_suspicious_tld": False,
            "is_shortener": rng.random() > 0.95,
            "url_entropy": rng.uniform(3.0, 4.2),
            "domain_entropy": rng.uniform(2.5, 3.8),
            "suspicious_keyword_count": 0,
            "has_suspicious_keywords": False,
            "domain_age_days": rng.randint(365, 7300),
            "is_new_domain": False,
            "ssl_valid": rng.random() > 0.05,
            "ssl_days_remaining": rng.randint(30, 365),
            "has_dns_record": True,
            "dns_record_count": rng.randint(2, 10),
        }
        features_list.append(features)
        labels.append(0)

    # ─── Generate Phishing URL Features ────────────────────
    for _ in range(n_phish):
        features = {
            "url_length": rng.randint(50, 250),
            "hostname_length": rng.randint(15, 80),
            "path_length": rng.randint(10, 100),
            "query_length": rng.randint(0, 80),
            "num_dots": rng.randint(2, 8),
            "num_hyphens": rng.randint(1, 6),
            "num_underscores": rng.randint(0, 3),
            "num_slashes": rng.randint(3, 10),
            "num_query_params": rng.randint(0, 5),
            "num_at_signs": int(rng.random() > 0.8),
            "num_ampersands": rng.randint(0, 3),
            "num_percent": rng.randint(0, 5),
            "path_depth": rng.randint(2, 8),
            "has_ip_address": rng.random() > 0.7,
            "is_https": rng.random() > 0.5,  # Only 50% HTTPS
            "has_port": rng.random() > 0.85,
            "has_at_sign": rng.random() > 0.8,
            "has_double_slash_redirect": rng.random() > 0.8,
            "has_hex_encoding": rng.random() > 0.5,
            "subdomain_count": rng.choice([1, 2, 3, 4], p=[0.2, 0.3, 0.3, 0.2]),
            "is_suspicious_tld": rng.random() > 0.4,
            "is_shortener": rng.random() > 0.85,
            "url_entropy": rng.uniform(4.0, 5.5),
            "domain_entropy": rng.uniform(3.5, 5.0),
            "suspicious_keyword_count": rng.randint(1, 5),
            "has_suspicious_keywords": True,
            "domain_age_days": rng.choice(
                [rng.randint(0, 30), rng.randint(30, 180), -1],
                p=[0.6, 0.3, 0.1],
            ),
            "is_new_domain": rng.random() > 0.3,
            "ssl_valid": rng.random() > 0.6,
            "ssl_days_remaining": rng.choice([rng.randint(-30, 30), rng.randint(30, 180)]),
            "has_dns_record": rng.random() > 0.2,
            "dns_record_count": rng.randint(0, 3),
        }
        features_list.append(features)
        labels.append(1)

    # Convert to numeric vectors
    X = np.array([
        [
            float(f.get(name, 0)) if isinstance(f.get(name, 0), (int, float))
            else (1.0 if f.get(name, False) else 0.0)
            for name in FEATURE_NAMES
        ]
        for f in features_list
    ])
    y = np.array(labels)

    return X, y


def train_model(X: np.ndarray, y: np.ndarray, evaluate: bool = True) -> XGBClassifier:
    """
    Train an XGBoost classifier on the provided dataset.
    """
    logger.info("Dataset shape: X=%s, y=%s", X.shape, y.shape)
    logger.info("Class distribution: 0 (legit)=%d, 1 (phish)=%d",
                np.sum(y == 0), np.sum(y == 1))

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train XGBoost
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="logloss",
        use_label_encoder=False,
    )

    logger.info("Training XGBoost model...")
    model.fit(X_train, y_train)

    if evaluate:
        # Evaluate on test set
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]

        accuracy = accuracy_score(y_test, y_pred)
        auc_score = roc_auc_score(y_test, y_proba)

        logger.info("\n" + "=" * 50)
        logger.info("MODEL EVALUATION RESULTS")
        logger.info("=" * 50)
        logger.info("Accuracy: %.4f", accuracy)
        logger.info("AUC-ROC:  %.4f", auc_score)
        logger.info("\nClassification Report:")
        logger.info("\n%s", classification_report(
            y_test, y_pred, target_names=["Legitimate", "Phishing"]
        ))
        logger.info("Confusion Matrix:")
        logger.info("\n%s", confusion_matrix(y_test, y_pred))

        # Cross-validation
        cv_scores = cross_val_score(model, X, y, cv=5, scoring="accuracy")
        logger.info("\n5-Fold CV Accuracy: %.4f (+/- %.4f)", cv_scores.mean(), cv_scores.std())

        # Feature importance
        logger.info("\nTop 10 Most Important Features:")
        importance = model.feature_importances_
        indices = np.argsort(importance)[::-1][:10]
        for i, idx in enumerate(indices):
            logger.info("  %d. %s: %.4f", i + 1, FEATURE_NAMES[idx], importance[idx])

    return model


def save_model(model: XGBClassifier):
    """Save the trained model to disk."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    logger.info("Model saved to %s", MODEL_PATH)


def main():
    parser = argparse.ArgumentParser(description="Train ThreatLens phishing detection model")
    parser.add_argument("--evaluate", action="store_true", help="Run evaluation after training")
    parser.add_argument("--samples", type=int, default=2000, help="Number of synthetic samples")
    args = parser.parse_args()

    # Generate synthetic dataset (replace with real data later)
    X, y = generate_synthetic_dataset(n_samples=args.samples)

    # Train model
    model = train_model(X, y, evaluate=args.evaluate)

    # Save model
    save_model(model)

    logger.info("✅ Training complete!")


if __name__ == "__main__":
    main()

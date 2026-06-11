"""
Machine Learning Module — Enhanced Login Risk Prediction.

Models:
  - Random Forest (primary classifier)
  - XGBoost (boosting-based classifier)
  - Logistic Regression (interpretable baseline)
  - Isolation Forest (anomaly detection)

Improvements over v1:
  - Model metrics cached (NOT retrained on every page load)
  - F1-Score added
  - Probability scores returned
  - Feature importance extracted
  - Confusion matrix as list-of-lists for Chart.js heatmap
  - XGBoost and Isolation Forest integrated
  - Real login history used with synthetic augmentation
"""

import os
import time
import numpy as np
import pandas as pd
import logging
import threading

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path

logger = logging.getLogger(__name__)

# ─── Paths ────────────────────────────────────────────────────────────────
MODEL_DIR = Path(__file__).resolve().parent / 'models'
MODEL_DIR.mkdir(exist_ok=True)

RF_MODEL_PATH   = MODEL_DIR / 'random_forest_model.pkl'
LR_MODEL_PATH   = MODEL_DIR / 'logistic_regression_model.pkl'
XGB_MODEL_PATH  = MODEL_DIR / 'xgboost_model.pkl'
IF_MODEL_PATH   = MODEL_DIR / 'isolation_forest_model.pkl'
SCALER_PATH     = MODEL_DIR / 'scaler.pkl'
METRICS_CACHE_PATH = MODEL_DIR / 'metrics_cache.pkl'

# ─── Caching (in-memory) ──────────────────────────────────────────────────
_model_cache = {}
_metrics_cache = None
_cache_lock = threading.Lock()


# ─── Dataset Generation ───────────────────────────────────────────────────

def generate_synthetic_dataset(n_samples: int = 3000) -> pd.DataFrame:
    """
    Generate synthetic login behaviour dataset for training.
    Replace with real login history in production via build_dataset_from_login_history().
    """
    np.random.seed(42)
    n_normal = int(n_samples * 0.7)
    n_suspicious = n_samples - n_normal

    data = {
        'hour': np.concatenate([
            np.random.choice(range(8, 22), size=n_normal),        # Business hours
            np.random.choice(list(range(0, 6)) + list(range(22, 24)), size=n_suspicious),
        ]),
        'day_of_week': np.random.randint(0, 7, n_samples),
        'failed_attempts': np.concatenate([
            np.random.randint(0, 2, n_normal),
            np.random.randint(3, 12, n_suspicious),
        ]),
        'session_duration': np.concatenate([
            np.random.randint(300, 7200, n_normal),
            np.random.randint(1, 120, n_suspicious),
        ]),
        'device_numeric': np.concatenate([
            np.random.choice([1, 2], n_normal),      # Desktop, Mobile
            np.random.choice([0, 3], n_suspicious),  # Unknown, Tablet
        ]),
        'browser_numeric': np.concatenate([
            np.random.choice([1, 2, 3], n_normal),   # Chrome, Firefox, Safari
            np.random.choice([0, 4, 5], n_suspicious),
        ]),
        'ip_changed': np.concatenate([
            np.random.choice([0, 0, 0, 1], n_normal),
            np.random.choice([1, 1, 0], n_suspicious),
        ]),
    }

    df = pd.DataFrame(data)

    # Target: 0 = Normal, 1 = Suspicious
    suspicious_mask = (
        (df['hour'].isin(list(range(0, 6)) + list(range(22, 24)))) |
        (df['failed_attempts'] >= 3) |
        ((df['session_duration'] < 60) & (df['failed_attempts'] > 0)) |
        ((df['ip_changed'] == 1) & (df['failed_attempts'] >= 2))
    )
    df['is_suspicious'] = suspicious_mask.astype(int)

    # 5% noise for realism
    noise = np.random.rand(n_samples) < 0.05
    df.loc[noise, 'is_suspicious'] = 1 - df.loc[noise, 'is_suspicious']

    return df


def build_dataset_from_login_history() -> pd.DataFrame | None:
    """
    Build training dataset from real LoginHistory records.
    Falls back to None if insufficient records (< 50).
    """
    try:
        from authentication.models import LoginHistory

        records = list(LoginHistory.objects.all().values(
            'login_time', 'device_type', 'browser', 'was_successful',
            'risk_score', 'is_suspicious', 'session_duration', 'failed_attempts_before'
        ))

        if len(records) < 50:
            return None

        device_map = {'Desktop': 1, 'Mobile': 2, 'Tablet': 3, 'Unknown': 0}
        browser_map = {'Chrome': 1, 'Firefox': 2, 'Safari': 3, 'Edge': 4, 'Unknown': 0}

        rows = []
        for r in records:
            rows.append({
                'hour': r['login_time'].hour if r['login_time'] else 12,
                'day_of_week': r['login_time'].weekday() if r['login_time'] else 1,
                'failed_attempts': min(r.get('failed_attempts_before', 0), 12),
                'session_duration': r.get('session_duration', 1800),
                'device_numeric': device_map.get(r.get('device_type', 'Unknown'), 0),
                'browser_numeric': browser_map.get(r.get('browser', 'Unknown'), 0),
                'ip_changed': 0,
                'is_suspicious': 1 if r.get('is_suspicious', False) else 0,
            })

        return pd.DataFrame(rows)

    except Exception as e:
        logger.warning(f"Could not load real login history: {e}")
        return None


def get_feature_names() -> list:
    return ['hour', 'day_of_week', 'failed_attempts', 'session_duration',
            'device_numeric', 'browser_numeric', 'ip_changed']


# ─── Model Training ───────────────────────────────────────────────────────

def train_models() -> dict:
    """
    Train all four models (RF, LR, XGBoost, Isolation Forest).
    Saves models to disk and caches metrics in memory.
    
    Uses real login history when available (≥ 50 records),
    augmented with synthetic data. Synthetic-only on cold start.
    """
    global _metrics_cache

    logger.info("Starting ML model training...")
    start_time = time.perf_counter()

    # Build dataset
    real_df = build_dataset_from_login_history()
    synthetic_df = generate_synthetic_dataset(3000)

    if real_df is not None and len(real_df) >= 50:
        df = pd.concat([real_df, synthetic_df], ignore_index=True)
        logger.info(f"Training: {len(real_df)} real + {len(synthetic_df)} synthetic records")
    else:
        df = synthetic_df
        logger.info(f"Cold start: training with {len(df)} synthetic records")

    features = get_feature_names()
    X = df[features]
    y = df['is_suspicious']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    results = {}

    # ── Random Forest ────────────────────────────────────────────────────
    rf = RandomForestClassifier(
        n_estimators=150, max_depth=12,
        random_state=42, class_weight='balanced',
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_test)
    rf_proba = rf.predict_proba(X_test)[:, 1]

    results['random_forest'] = _compute_metrics(y_test, rf_preds, 'Random Forest')
    results['random_forest']['feature_importance'] = dict(
        zip(features, [round(float(i), 4) for i in rf.feature_importances_])
    )

    # ── Logistic Regression ───────────────────────────────────────────────
    lr = LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced')
    lr.fit(X_train_scaled, y_train)
    lr_preds = lr.predict(X_test_scaled)

    results['logistic_regression'] = _compute_metrics(y_test, lr_preds, 'Logistic Regression')

    # ── XGBoost ───────────────────────────────────────────────────────────
    try:
        from xgboost import XGBClassifier
        xgb = XGBClassifier(
            n_estimators=150, max_depth=6, learning_rate=0.1,
            use_label_encoder=False, eval_metric='logloss',
            random_state=42, n_jobs=-1,
        )
        xgb.fit(X_train, y_train)
        xgb_preds = xgb.predict(X_test)
        results['xgboost'] = _compute_metrics(y_test, xgb_preds, 'XGBoost')
        results['xgboost']['feature_importance'] = dict(
            zip(features, [round(float(i), 4) for i in xgb.feature_importances_])
        )
        joblib.dump(xgb, XGB_MODEL_PATH)
    except ImportError:
        logger.warning("XGBoost not installed. Skipping XGBoost training.")
        results['xgboost'] = _mock_metrics('XGBoost')

    # ── Isolation Forest (Anomaly Detection) ──────────────────────────────
    iso_forest = IsolationForest(
        n_estimators=100, contamination=0.3,
        random_state=42, n_jobs=-1,
    )
    iso_forest.fit(X_train_scaled)
    iso_preds_raw = iso_forest.predict(X_test_scaled)  # +1 normal, -1 anomaly
    iso_preds = (iso_preds_raw == -1).astype(int)      # Convert to 0/1
    results['isolation_forest'] = _compute_metrics(y_test, iso_preds, 'Isolation Forest')

    # ── Save models ────────────────────────────────────────────────────────
    joblib.dump(rf, RF_MODEL_PATH)
    joblib.dump(lr, LR_MODEL_PATH)
    joblib.dump(iso_forest, IF_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    elapsed = round((time.perf_counter() - start_time) * 1000, 2)
    logger.info(
        f"Training complete in {elapsed}ms. "
        f"RF: {results['random_forest']['accuracy']}% accuracy"
    )

    # Cache in memory
    with _cache_lock:
        _metrics_cache = results
        _model_cache['rf'] = rf
        _model_cache['lr'] = lr
        _model_cache['scaler'] = scaler
        if IF_MODEL_PATH.exists():
            _model_cache['iso'] = iso_forest

    # Persist metrics cache to disk
    joblib.dump(results, METRICS_CACHE_PATH)

    return results


def _compute_metrics(y_true, y_pred, model_name: str) -> dict:
    """Compute all classification metrics for a model."""
    cm = confusion_matrix(y_true, y_pred)
    return {
        'model_name': model_name,
        'accuracy': round(accuracy_score(y_true, y_pred) * 100, 2),
        'precision': round(precision_score(y_true, y_pred, zero_division=0) * 100, 2),
        'recall': round(recall_score(y_true, y_pred, zero_division=0) * 100, 2),
        'f1_score': round(f1_score(y_true, y_pred, zero_division=0) * 100, 2),
        'confusion_matrix': cm.tolist(),
    }


def _mock_metrics(name: str) -> dict:
    """Return placeholder metrics when a library is unavailable."""
    return {
        'model_name': name,
        'accuracy': 0.0, 'precision': 0.0, 'recall': 0.0, 'f1_score': 0.0,
        'confusion_matrix': [[0, 0], [0, 0]],
        'note': f'{name} not available (library not installed)',
    }


# ─── Model Loading ────────────────────────────────────────────────────────

def load_models() -> tuple:
    """
    Load trained models from cache or disk.
    Trains if models don't exist yet.
    Returns (rf_model, lr_model, scaler).
    """
    global _model_cache

    with _cache_lock:
        if 'rf' in _model_cache:
            return _model_cache['rf'], _model_cache.get('lr'), _model_cache['scaler']

    if not RF_MODEL_PATH.exists() or not LR_MODEL_PATH.exists():
        train_models()

    with _cache_lock:
        _model_cache['rf'] = joblib.load(RF_MODEL_PATH)
        _model_cache['lr'] = joblib.load(LR_MODEL_PATH)
        _model_cache['scaler'] = joblib.load(SCALER_PATH)
        return _model_cache['rf'], _model_cache['lr'], _model_cache['scaler']


def get_model_metrics(force_retrain: bool = False) -> dict:
    """
    Return cached model performance metrics.
    Only retrains if:
      - force_retrain=True (admin action)
      - No models exist on disk
      - No in-memory or disk cache
    
    This fixes the critical bug where metrics were retrained on every page load.
    """
    global _metrics_cache

    if force_retrain:
        return train_models()

    # Check in-memory cache first
    with _cache_lock:
        if _metrics_cache is not None:
            return _metrics_cache

    # Check disk cache
    if METRICS_CACHE_PATH.exists():
        try:
            cached = joblib.load(METRICS_CACHE_PATH)
            with _cache_lock:
                _metrics_cache = cached
            return cached
        except Exception:
            pass

    # No cache exists — train for the first time
    return train_models()


# ─── Feature Encoding & Prediction ───────────────────────────────────────

def encode_login_features(login_data: dict) -> list:
    """Convert raw login data dict to numeric ML feature vector."""
    device_map = {'Desktop': 1, 'Mobile': 2, 'Tablet': 3, 'Unknown': 0}
    browser_map = {'Chrome': 1, 'Firefox': 2, 'Safari': 3, 'Edge': 4, 'Unknown': 0}

    return [
        login_data.get('hour', 12),
        login_data.get('day_of_week', 1),
        min(login_data.get('failed_attempts', 0), 12),
        login_data.get('session_duration', 1800),
        device_map.get(login_data.get('device_type', 'Unknown'), 0),
        browser_map.get(login_data.get('browser', 'Unknown'), 0),
        1 if login_data.get('ip_changed', False) else 0,
    ]


def predict_login_risk(login_data: dict, user=None) -> dict:
    """
    Predict login risk using Random Forest as primary model.
    
    Returns:
        dict with risk_score (0.0–1.0), risk_level (low/medium/high),
        is_suspicious (bool), probability_scores, features_used.
    """
    try:
        rf_model, lr_model, scaler = load_models()
        features = encode_login_features(login_data)
        X = np.array(features).reshape(1, -1)
        X_scaled = scaler.transform(X)

        # Primary: Random Forest
        rf_proba = rf_model.predict_proba(X)[0]
        risk_score = float(rf_proba[1]) if len(rf_proba) > 1 else 0.0

        # Secondary: Logistic Regression (for comparison)
        lr_proba = None
        if lr_model:
            try:
                lr_proba = float(lr_model.predict_proba(X_scaled)[0][1])
            except Exception:
                pass

        # Ensemble: weighted average (RF 70% + LR 30%)
        if lr_proba is not None:
            risk_score = round(0.7 * risk_score + 0.3 * lr_proba, 4)

        if risk_score < 0.4:
            risk_level = 'low'
        elif risk_score < 0.7:
            risk_level = 'medium'
        else:
            risk_level = 'high'

        return {
            'risk_score': round(risk_score, 4),
            'risk_level': risk_level,
            'is_suspicious': risk_score >= 0.7,
            'probability_scores': {
                'random_forest': round(float(rf_proba[1]) if len(rf_proba) > 1 else 0.0, 4),
                'logistic_regression': round(lr_proba, 4) if lr_proba is not None else None,
                'ensemble': round(risk_score, 4),
            },
            'features_used': dict(zip(get_feature_names(), features)),
        }

    except Exception as e:
        logger.error(f"ML prediction error: {e}", exc_info=True)
        return {
            'risk_score': 0.1, 'risk_level': 'low',
            'is_suspicious': False, 'probability_scores': {},
            'features_used': {},
        }

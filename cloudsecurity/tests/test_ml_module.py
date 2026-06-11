"""
ML module tests — covers model training, prediction, caching, and IDS.
"""
import time
from django.test import TestCase

from ml_module.predictor import (
    generate_synthetic_dataset, train_models, get_model_metrics,
    predict_login_risk, encode_login_features, get_feature_names,
    _metrics_cache, _model_cache, _cache_lock,
)
from audit.intrusion_detection import IntrusionDetectionService
from authentication.models import CustomUser, LoginHistory


class SyntheticDatasetTest(TestCase):
    """Test synthetic dataset generation."""

    def test_dataset_shape(self):
        df = generate_synthetic_dataset(500)
        self.assertEqual(len(df), 500)
        expected_cols = {'hour', 'day_of_week', 'failed_attempts', 'session_duration',
                         'device_numeric', 'browser_numeric', 'ip_changed', 'is_suspicious'}
        self.assertTrue(expected_cols.issubset(set(df.columns)))

    def test_dataset_has_both_classes(self):
        df = generate_synthetic_dataset(1000)
        counts = df['is_suspicious'].value_counts()
        self.assertIn(0, counts.index)
        self.assertIn(1, counts.index)
        # Check at least 10% of each class
        self.assertGreater(counts[1] / len(df), 0.1)

    def test_feature_names_length(self):
        features = get_feature_names()
        self.assertEqual(len(features), 7)

    def test_encode_login_features_returns_7_values(self):
        login_data = {
            'hour': 14,
            'day_of_week': 1,
            'failed_attempts': 0,
            'session_duration': 3600,
            'device_type': 'Desktop',
            'browser': 'Chrome',
            'ip_changed': False,
        }
        features = encode_login_features(login_data)
        self.assertEqual(len(features), 7)
        self.assertEqual(features[0], 14)  # hour
        self.assertEqual(features[4], 1)   # Desktop = 1


class ModelTrainingTest(TestCase):
    """Test model training and metric generation."""

    def test_train_returns_all_model_keys(self):
        metrics = train_models()
        self.assertIn('random_forest', metrics)
        self.assertIn('logistic_regression', metrics)
        # XGBoost may or may not be available
        self.assertIn('isolation_forest', metrics)

    def test_random_forest_accuracy_above_threshold(self):
        metrics = train_models()
        rf_acc = metrics['random_forest']['accuracy']
        self.assertGreater(rf_acc, 70.0)  # Should be > 70% accurate

    def test_metrics_include_f1_score(self):
        metrics = train_models()
        self.assertIn('f1_score', metrics['random_forest'])
        self.assertIn('f1_score', metrics['logistic_regression'])

    def test_metrics_include_confusion_matrix(self):
        metrics = train_models()
        cm = metrics['random_forest']['confusion_matrix']
        self.assertIsInstance(cm, list)
        self.assertEqual(len(cm), 2)
        self.assertEqual(len(cm[0]), 2)

    def test_feature_importance_present(self):
        metrics = train_models()
        fi = metrics['random_forest'].get('feature_importance')
        self.assertIsNotNone(fi)
        self.assertEqual(len(fi), 7)


class ModelCachingTest(TestCase):
    """Test model metrics caching — MUST not retrain on every call."""

    def test_second_call_uses_cache(self):
        # First call trains
        m1 = get_model_metrics(force_retrain=True)
        # Second call should use cache (fast)
        start = time.perf_counter()
        m2 = get_model_metrics(force_retrain=False)
        elapsed = time.perf_counter() - start

        # Cached call should be nearly instant (< 500ms)
        self.assertLess(elapsed, 0.5)
        self.assertEqual(m1['random_forest']['accuracy'], m2['random_forest']['accuracy'])

    def test_force_retrain_updates_cache(self):
        m1 = get_model_metrics(force_retrain=True)
        m2 = get_model_metrics(force_retrain=True)
        # Both should have same structure (deterministic with seed)
        self.assertIn('random_forest', m1)
        self.assertIn('random_forest', m2)


class RiskPredictionTest(TestCase):
    """Test login risk prediction."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        train_models()  # Train once for all prediction tests

    def test_normal_login_low_risk(self):
        result = predict_login_risk({
            'hour': 10,          # Business hours
            'day_of_week': 1,    # Tuesday
            'failed_attempts': 0,
            'session_duration': 3600,
            'device_type': 'Desktop',
            'browser': 'Chrome',
            'ip_changed': False,
        })
        self.assertIn('risk_score', result)
        self.assertIn('risk_level', result)
        self.assertGreaterEqual(result['risk_score'], 0.0)
        self.assertLessEqual(result['risk_score'], 1.0)
        # Normal login should NOT be high risk
        self.assertNotEqual(result['risk_level'], 'high')

    def test_suspicious_login_higher_risk(self):
        suspicious_result = predict_login_risk({
            'hour': 2,           # 2am
            'day_of_week': 6,   # Sunday
            'failed_attempts': 8,
            'session_duration': 30,
            'device_type': 'Unknown',
            'browser': 'Unknown',
            'ip_changed': True,
        })
        normal_result = predict_login_risk({
            'hour': 10,
            'day_of_week': 1,
            'failed_attempts': 0,
            'session_duration': 3600,
            'device_type': 'Desktop',
            'browser': 'Chrome',
            'ip_changed': False,
        })
        # Suspicious should be riskier than normal
        self.assertGreater(suspicious_result['risk_score'], normal_result['risk_score'])

    def test_prediction_returns_probability_scores(self):
        result = predict_login_risk({
            'hour': 12, 'day_of_week': 2, 'failed_attempts': 0,
            'session_duration': 1800, 'device_type': 'Mobile',
            'browser': 'Safari', 'ip_changed': False,
        })
        self.assertIn('probability_scores', result)
        self.assertIn('random_forest', result['probability_scores'])

    def test_prediction_returns_features_used(self):
        result = predict_login_risk({
            'hour': 12, 'day_of_week': 2, 'failed_attempts': 0,
            'session_duration': 1800, 'device_type': 'Mobile',
            'browser': 'Safari', 'ip_changed': False,
        })
        self.assertIn('features_used', result)
        self.assertEqual(len(result['features_used']), 7)

    def test_model_failure_returns_safe_defaults(self):
        """If ML fails, should return a safe low-risk default (not crash)."""
        result = predict_login_risk({})  # Empty features
        self.assertIn('risk_score', result)
        self.assertIsNotNone(result['risk_score'])


class IntrusionDetectionTest(TestCase):
    """Test the Intrusion Detection System."""

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            username='ids_test', email='ids@example.com', password='pass',
            email_verified=True, status='active', last_login_ip='10.0.0.1',
        )

    def test_brute_force_detection_creates_event(self):
        # Create 5 failed logins in DB
        for _ in range(5):
            LoginHistory.objects.create(
                user=self.user, ip_address='192.168.1.100',
                was_successful=False, device_type='Desktop', browser='Chrome',
            )
        from audit.models import SecurityEvent
        events = IntrusionDetectionService.analyse_login_attempt(
            self.user, '192.168.1.100', False
        )
        # Should have created a brute force event
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user, event_type='brute_force'
            ).exists()
        )

    def test_ip_change_detection(self):
        from audit.models import SecurityEvent
        # User logs in from a different IP
        events = IntrusionDetectionService.analyse_login_attempt(
            self.user, '10.0.0.99',  # Different from last_login_ip='10.0.0.1'
            was_successful=True,
        )
        self.assertTrue(
            SecurityEvent.objects.filter(
                user=self.user, event_type='unusual_location'
            ).exists()
        )

    def test_threat_summary_returns_counts(self):
        summary = IntrusionDetectionService.get_threat_summary()
        self.assertIn('unresolved_count', summary)
        self.assertIn('brute_force_count', summary)
        self.assertIn('ip_change_count', summary)
        self.assertIn('suspicious_logins', summary)
        self.assertIsInstance(summary['unresolved_count'], int)

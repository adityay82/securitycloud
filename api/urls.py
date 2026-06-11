from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

app_name = 'api'

urlpatterns = [
    # ── Authentication ────────────────────────────────────────────────
    path('auth/register/', views.RegisterAPIView.as_view(), name='register'),
    path('auth/login/', views.LoginAPIView.as_view(), name='login'),
    path('auth/verify-otp/', views.VerifyOTPAPIView.as_view(), name='verify_otp'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/logout/', views.LogoutAPIView.as_view(), name='logout'),

    # ── Files ─────────────────────────────────────────────────────────
    path('files/', views.FileListAPIView.as_view(), name='file_list'),
    path('files/upload/', views.FileUploadAPIView.as_view(), name='file_upload'),
    path('files/<uuid:file_id>/', views.FileDetailAPIView.as_view(), name='file_detail'),
    path('files/<uuid:file_id>/integrity/', views.FileIntegrityAPIView.as_view(), name='file_integrity'),

    # ── Machine Learning ──────────────────────────────────────────────
    path('ml/risk-score/', views.RiskScoreAPIView.as_view(), name='risk_score'),
    path('ml/model-metrics/', views.ModelMetricsAPIView.as_view(), name='model_metrics'),
    path('ml/retrain/', views.RetrainModelAPIView.as_view(), name='retrain'),

    # ── Audit ─────────────────────────────────────────────────────────
    path('audit/logs/', views.AuditLogAPIView.as_view(), name='audit_logs'),
    path('audit/events/', views.SecurityEventsAPIView.as_view(), name='security_events'),
    path('audit/events/<uuid:event_id>/', views.SecurityEventsAPIView.as_view(), name='resolve_event'),
    path('audit/export/', views.AuditExportAPIView.as_view(), name='audit_export'),

    # ── Dashboard ─────────────────────────────────────────────────────
    path('dashboard/stats/', views.DashboardStatsAPIView.as_view(), name='dashboard_stats'),
    path('dashboard/login-trend/', views.LoginTrendAPIView.as_view(), name='login_trend'),
]

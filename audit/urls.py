from django.urls import path
from . import views

app_name = 'audit'

urlpatterns = [
    path('logs/', views.audit_log_view, name='logs'),
    path('logs/export/', views.export_audit_csv, name='export_csv'),
    path('security-events/', views.security_events_view, name='security_events'),
    path('api/stats/', views.audit_stats_api, name='stats_api'),
]

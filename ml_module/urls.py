from django.urls import path
from . import views

app_name = 'ml_module'

urlpatterns = [
    path('dashboard/', views.ml_dashboard_view, name='dashboard'),
    path('api/metrics/', views.model_metrics_api, name='metrics_api'),
    path('api/retrain/', views.retrain_api, name='retrain_api'),
    path('api/predictions/', views.risk_predictions_api, name='predictions_api'),
]

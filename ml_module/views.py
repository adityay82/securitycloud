"""
ML module views — upgraded to use CBVs and cached metrics.
"""
import logging
from django.shortcuts import render
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import JsonResponse
from django.views import View
from django.views.decorators.http import require_POST
from django.utils.decorators import method_decorator

from .predictor import get_model_metrics, train_models
from authentication.models import LoginHistory

logger = logging.getLogger(__name__)


class MLDashboardView(LoginRequiredMixin, View):
    """ML security analytics dashboard."""

    def get(self, request):
        # Metrics are CACHED — does NOT retrain
        metrics = get_model_metrics(force_retrain=False)

        if request.user.role == 'admin':
            predictions = LoginHistory.objects.select_related('user').filter(
                risk_score__gt=0
            ).order_by('-login_time')[:50]
            risk_stats = {
                'low': LoginHistory.objects.filter(risk_level='low').count(),
                'medium': LoginHistory.objects.filter(risk_level='medium').count(),
                'high': LoginHistory.objects.filter(risk_level='high').count(),
            }
        else:
            predictions = LoginHistory.objects.filter(
                user=request.user, risk_score__gt=0
            ).order_by('-login_time')[:20]
            risk_stats = {
                'low': predictions.filter(risk_level='low').count(),
                'medium': predictions.filter(risk_level='medium').count(),
                'high': predictions.filter(risk_level='high').count(),
            }

        return render(request, 'ml_module/dashboard.html', {
            'metrics': metrics,
            'predictions': predictions,
            'risk_stats': risk_stats,
            'page_title': 'ML Security Analytics',
        })


class ModelMetricsAPIView(LoginRequiredMixin, View):
    """AJAX: Return cached model metrics for Chart.js."""

    def get(self, request):
        metrics = get_model_metrics(force_retrain=False)
        return JsonResponse(metrics)


class RetrainAPIView(LoginRequiredMixin, View):
    """Admin-only: Force retrain ML models."""

    @method_decorator(require_POST)
    def post(self, request):
        if request.user.role != 'admin':
            return JsonResponse({'error': 'Unauthorized'}, status=403)
        try:
            metrics = train_models()
            return JsonResponse({'success': True, 'metrics': metrics})
        except Exception as e:
            logger.error(f"Retrain error: {e}")
            return JsonResponse({'success': False, 'error': str(e)}, status=500)


class RiskPredictionsAPIView(LoginRequiredMixin, View):
    """AJAX: Risk distribution summary."""

    def get(self, request):
        if request.user.role == 'admin':
            qs = LoginHistory.objects.all()
        else:
            qs = LoginHistory.objects.filter(user=request.user)

        return JsonResponse({
            'low': qs.filter(risk_level='low').count(),
            'medium': qs.filter(risk_level='medium').count(),
            'high': qs.filter(risk_level='high').count(),
            'total': qs.count(),
            'suspicious': qs.filter(is_suspicious=True).count(),
        })


# URL aliases
ml_dashboard_view = MLDashboardView.as_view()
model_metrics_api = ModelMetricsAPIView.as_view()
retrain_api = RetrainAPIView.as_view()
risk_predictions_api = RiskPredictionsAPIView.as_view()

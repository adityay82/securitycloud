from django.contrib import admin
from .models import ThreatPrediction

@admin.register(ThreatPrediction)
class ThreatPredictionAdmin(admin.ModelAdmin):
    list_display = ['user', 'risk_level', 'risk_score', 'is_suspicious', 'predicted_at']
    list_filter = ['risk_level', 'is_suspicious']

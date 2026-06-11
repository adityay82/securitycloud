from django.db import models
from django.conf import settings
import uuid


class ThreatPrediction(models.Model):
    """Store ML threat predictions for analysis."""
    RISK_CHOICES = [('low', 'Low'), ('medium', 'Medium'), ('high', 'High')]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name='threat_predictions')
    risk_score = models.FloatField()
    risk_level = models.CharField(max_length=10, choices=RISK_CHOICES)
    is_suspicious = models.BooleanField(default=False)
    login_hour = models.IntegerField()
    device_type = models.CharField(max_length=50)
    browser = models.CharField(max_length=100)
    failed_attempts = models.IntegerField(default=0)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    action_taken = models.CharField(max_length=100, default='none')
    predicted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'threat_predictions'
        ordering = ['-predicted_at']

    def __str__(self):
        return f"{self.user.username} - {self.risk_level} ({self.risk_score:.2f})"

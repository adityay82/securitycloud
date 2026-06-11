from django.contrib import admin
from .models import AuditLog, SecurityEvent

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['action', 'user', 'severity', 'timestamp', 'ip_address']
    list_filter = ['severity', 'action']

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ['event_type', 'user', 'risk_score', 'is_resolved', 'detected_at']

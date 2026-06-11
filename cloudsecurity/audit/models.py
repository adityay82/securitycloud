from django.db import models
from django.conf import settings
import uuid


class AuditLog(models.Model):
    """Comprehensive audit logging for all security events."""
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    ACTION_CHOICES = [
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('logout', 'Logout'),
        ('suspicious_login_detected', 'Suspicious Login Detected'),
        ('suspicious_access', 'Suspicious Access Attempt'),
        ('otp_sent', 'OTP Sent'),
        ('otp_verified', 'OTP Verified'),
        ('otp_failed', 'OTP Verification Failed'),
        ('file_uploaded', 'File Uploaded'),
        ('file_encrypted', 'File Encrypted'),
        ('file_decrypted', 'File Decrypted'),
        ('file_downloaded', 'File Downloaded'),
        ('file_deleted', 'File Deleted'),
        ('file_integrity_check', 'File Integrity Check'),
        ('password_reset', 'Password Reset'),
        ('profile_updated', 'Profile Updated'),
        ('user_approved', 'User Approved'),
        ('user_suspended', 'User Suspended'),
        ('decryption_error', 'Decryption Error'),
        ('integrity_failed', 'File Integrity Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                             null=True, blank=True, related_name='audit_logs')
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='low')
    timestamp = models.DateTimeField(auto_now_add=True)
    extra_data = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'action']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['severity']),
        ]

    def __str__(self):
        return f"[{self.severity.upper()}] {self.action} - {self.user} at {self.timestamp}"


class SecurityEvent(models.Model):
    """High-severity security events requiring admin attention."""
    EVENT_TYPES = [
        ('brute_force', 'Brute Force Attempt'),
        ('unusual_location', 'Unusual Location'),
        ('multiple_failures', 'Multiple Auth Failures'),
        ('integrity_violation', 'File Integrity Violation'),
        ('suspicious_pattern', 'Suspicious Login Pattern'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                             related_name='security_events')
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    risk_score = models.FloatField(default=0.0)
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                    null=True, blank=True, related_name='resolved_events')
    detected_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'security_events'
        ordering = ['-detected_at']

    def __str__(self):
        return f"{self.event_type} - {self.user.username}"

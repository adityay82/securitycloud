from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import uuid


class CustomUser(AbstractUser):
    """Extended user model with cloud security fields and adaptive MFA."""

    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('user', 'User'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending Verification'),
        ('active', 'Active'),
        ('suspended', 'Suspended'),
    ]
    SECURITY_QUESTIONS = [
        ('pet', "What was the name of your first pet?"),
        ('school', "What primary school did you attend?"),
        ('city', "In what city were you born?"),
        ('mother', "What is your mother's maiden name?"),
        ('car', "What was the make of your first car?"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    phone = models.CharField(max_length=20, blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profiles/', blank=True, null=True)
    email_verified = models.BooleanField(default=False)
    two_factor_enabled = models.BooleanField(default=True)
    last_login_ip = models.GenericIPAddressField(blank=True, null=True)
    failed_login_count = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(blank=True, null=True)

    # Security question for medium-risk MFA
    security_question = models.CharField(
        max_length=50, choices=SECURITY_QUESTIONS, blank=True, null=True
    )
    security_answer = models.CharField(max_length=255, blank=True, null=True,
                                       help_text="Stored as lowercase plain text for demo. "
                                                 "Use hashed answers in production.")

    # Risk profile
    cumulative_risk_score = models.FloatField(default=0.0, help_text="Running average risk score")
    total_logins = models.IntegerField(default=0)
    total_suspicious_logins = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.username} ({self.role})"

    def is_locked(self):
        """Check if account is currently locked."""
        return bool(
            self.account_locked_until and
            self.account_locked_until > timezone.now()
        )

    def increment_failed_login(self):
        """
        Increment failed login counter.
        Lockout thresholds: 5 attempts → 30 min, 10 → 2 hrs, 15+ → 24 hrs.
        """
        self.failed_login_count += 1
        if self.failed_login_count >= 15:
            self.account_locked_until = timezone.now() + timezone.timedelta(hours=24)
        elif self.failed_login_count >= 10:
            self.account_locked_until = timezone.now() + timezone.timedelta(hours=2)
        elif self.failed_login_count >= 5:
            self.account_locked_until = timezone.now() + timezone.timedelta(minutes=30)
        self.save(update_fields=['failed_login_count', 'account_locked_until'])

    def reset_failed_login(self):
        """Reset lockout state after successful authentication."""
        self.failed_login_count = 0
        self.account_locked_until = None
        self.save(update_fields=['failed_login_count', 'account_locked_until'])

    def get_risk_badge_class(self):
        """Return CSS class for risk level badge."""
        if self.cumulative_risk_score >= 0.7:
            return 'badge-risk-high'
        elif self.cumulative_risk_score >= 0.4:
            return 'badge-risk-medium'
        return 'badge-risk-low'

    def get_risk_label(self):
        """Return human-readable risk label."""
        if self.cumulative_risk_score >= 0.7:
            return 'High'
        elif self.cumulative_risk_score >= 0.4:
            return 'Medium'
        return 'Low'


class OTPVerification(models.Model):
    """OTP model for multi-factor authentication."""
    PURPOSE_CHOICES = [
        ('login', 'Login Verification'),
        ('email', 'Email Verification'),
        ('password_reset', 'Password Reset'),
        ('risk_auth', 'Risk-Based Authentication'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='otps')
    otp_code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=20, choices=PURPOSE_CHOICES, default='login')
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.IntegerField(default=0)

    class Meta:
        db_table = 'otp_verification'
        indexes = [
            models.Index(fields=['user', 'purpose', 'is_used']),
            models.Index(fields=['expires_at']),
        ]

    def is_valid(self):
        """Check OTP is unused, not expired, and has attempts remaining."""
        return (
            not self.is_used and
            self.expires_at > timezone.now() and
            self.attempts < 3
        )

    def __str__(self):
        return f"OTP for {self.user.username} — {self.purpose}"


class LoginHistory(models.Model):
    """Complete login history with metadata for ML analysis and audit."""
    RISK_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='login_history')
    login_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    device_type = models.CharField(max_length=50, blank=True)
    browser = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=200, blank=True, default='Unknown')
    was_successful = models.BooleanField(default=True)
    risk_score = models.FloatField(default=0.0)
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS, default='low')
    is_suspicious = models.BooleanField(default=False)
    session_duration = models.IntegerField(default=0, help_text="Duration in seconds")
    failed_attempts_before = models.IntegerField(default=0)
    mfa_level_used = models.CharField(max_length=10, default='low',
                                      help_text="MFA level: low/medium/high")

    class Meta:
        db_table = 'login_history'
        ordering = ['-login_time']
        indexes = [
            models.Index(fields=['user', 'login_time']),
            models.Index(fields=['is_suspicious']),
            models.Index(fields=['ip_address']),
        ]

    def __str__(self):
        status = 'Success' if self.was_successful else 'Failed'
        return f"{self.user.username} — {self.login_time} — {status}"

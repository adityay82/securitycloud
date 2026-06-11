from django.db import models
from django.conf import settings
import uuid


class EncryptedFile(models.Model):
    """Encrypted file storage model with extended metadata."""
    ENCRYPTION_CHOICES = [
        ('AES-128', 'AES-128 (Small files < 1MB)'),
        ('AES-192', 'AES-192 (Medium files 1–10MB)'),
        ('AES-256', 'AES-256 (Large files > 10MB or high-risk)'),
    ]
    STATUS_CHOICES = [
        ('uploaded', 'Uploaded'),
        ('encrypted', 'Encrypted'),
        ('decrypted', 'Decrypted'),
        ('error', 'Error'),
    ]
    SENSITIVITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='files'
    )
    original_filename = models.CharField(max_length=255)
    file_path = models.FileField(upload_to='encrypted/')
    original_size = models.BigIntegerField(default=0)
    encryption_type = models.CharField(max_length=10, choices=ENCRYPTION_CHOICES, blank=True)
    encryption_key = models.TextField(blank=True,
                                      help_text='AES key wrapped with master key (AES-GCM). '
                                                'Production: use AWS KMS.')
    encryption_iv = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='uploaded')
    file_hash = models.CharField(max_length=64, blank=True,
                                  help_text='SHA-256 of original plaintext for integrity check')
    encryption_time = models.FloatField(default=0.0, help_text='Time in milliseconds')
    decryption_time = models.FloatField(default=0.0, help_text='Time in milliseconds')

    # Enhanced metadata
    sensitivity_level = models.CharField(
        max_length=10, choices=SENSITIVITY_CHOICES, default='medium'
    )
    risk_score_at_upload = models.FloatField(default=0.0,
                                              help_text='User risk score at time of upload')
    access_count = models.IntegerField(default=0, help_text='Number of times decrypted/downloaded')
    last_accessed = models.DateTimeField(null=True, blank=True)

    uploaded_at = models.DateTimeField(auto_now_add=True)
    encrypted_at = models.DateTimeField(blank=True, null=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        db_table = 'encrypted_files'
        ordering = ['-uploaded_at']
        indexes = [
            models.Index(fields=['user', 'is_deleted']),
            models.Index(fields=['status']),
            models.Index(fields=['encryption_type']),
        ]

    def __str__(self):
        return f"{self.original_filename} — {self.user.username} [{self.encryption_type}]"

    def get_size_mb(self):
        return round(self.original_size / (1024 * 1024), 2)

    def get_size_display(self):
        size = self.original_size
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        return f"{size / (1024 * 1024 * 1024):.1f} GB"

    def get_strength_class(self):
        """Return CSS class for encryption strength indicator."""
        strength_map = {
            'AES-128': 'text-warning',
            'AES-192': 'text-info',
            'AES-256': 'text-success',
        }
        return strength_map.get(self.encryption_type, 'text-muted')

    def get_strength_percent(self):
        """Return percentage for encryption strength bar."""
        strength_map = {'AES-128': 50, 'AES-192': 75, 'AES-256': 100}
        return strength_map.get(self.encryption_type, 0)

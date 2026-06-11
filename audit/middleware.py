"""Audit middleware to log security-relevant request metadata."""
import logging
from .models import AuditLog

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = ['/auth/login/', '/auth/register/', '/auth/verify-otp/', '/auth/forgot-password/']


class AuditMiddleware:
    """Log security-relevant requests automatically."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Log failed access attempts on sensitive paths
        if request.path in SENSITIVE_PATHS and response.status_code >= 400:
            user = request.user if request.user.is_authenticated else None
            try:
                AuditLog.objects.create(
                    user=user,
                    action='suspicious_access',
                    description=f'{request.method} {request.path} returned {response.status_code}',
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                    severity='medium'
                )
            except Exception as e:
                logger.error(f"AuditMiddleware logging error: {e}")

        # Log unauthorized access attempts (403 Forbidden)
        if response.status_code == 403 and request.user.is_authenticated:
            try:
                AuditLog.objects.create(
                    user=request.user,
                    action='suspicious_access',
                    description=f'Access denied: {request.method} {request.path}',
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                    severity='high'
                )
            except Exception as e:
                logger.error(f"AuditMiddleware logging error: {e}")

        return response

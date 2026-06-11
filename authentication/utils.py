import random
import string
import hashlib
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


def generate_otp(length=6):
    """Generate a cryptographically secure numeric OTP."""
    import secrets
    return ''.join([str(secrets.randbelow(10)) for _ in range(length)])


def send_otp_email(user, otp_code, purpose='login'):
    """Send OTP via email with professional template."""
    purpose_labels = {
        'login': 'Login Verification',
        'email': 'Email Verification',
        'password_reset': 'Password Reset',
        'risk_auth': 'Security Verification',
    }
    label = purpose_labels.get(purpose, 'Verification')

    subject = f"CloudSec — Your {label} OTP"
    message = f"""
Dear {user.get_full_name() or user.username},

Your One-Time Password (OTP) for {label} is:

    {otp_code}

This OTP is valid for {settings.OTP_EXPIRY_MINUTES} minutes.
Do not share this code with anyone.

If you did not request this, please secure your account immediately.

— CloudSec Security Team
"""
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        logger.info(f"OTP email sent to {user.email} for {purpose}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {user.email}: {e}")
        return False


def create_otp(user, purpose='login'):
    """Create and store OTP record, invalidate old ones."""
    from .models import OTPVerification

    # Invalidate existing OTPs for same purpose
    OTPVerification.objects.filter(
        user=user, purpose=purpose, is_used=False
    ).update(is_used=True)

    otp_code = generate_otp(settings.OTP_LENGTH)
    expires_at = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)

    otp_obj = OTPVerification.objects.create(
        user=user,
        otp_code=otp_code,
        purpose=purpose,
        expires_at=expires_at
    )
    return otp_obj


def verify_otp(user, otp_code, purpose='login'):
    """Verify OTP and mark as used."""
    from .models import OTPVerification

    try:
        otp_obj = OTPVerification.objects.get(
            user=user,
            otp_code=otp_code,
            purpose=purpose,
            is_used=False,
        )
        otp_obj.attempts += 1

        if not otp_obj.is_valid():
            otp_obj.save()
            return False, "OTP has expired or is invalid."

        otp_obj.is_used = True
        otp_obj.save()
        return True, "OTP verified successfully."

    except OTPVerification.DoesNotExist:
        return False, "Invalid OTP code."


def get_client_ip(request):
    """Extract real client IP address."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


def get_device_info(request):
    """Parse user-agent for device and browser info."""
    user_agent = request.META.get('HTTP_USER_AGENT', '')

    device = 'Desktop'
    if any(x in user_agent for x in ['Mobile', 'Android', 'iPhone', 'iPad']):
        device = 'Mobile'
    elif 'Tablet' in user_agent:
        device = 'Tablet'

    browser = 'Unknown'
    if 'Chrome' in user_agent and 'Edge' not in user_agent:
        browser = 'Chrome'
    elif 'Firefox' in user_agent:
        browser = 'Firefox'
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        browser = 'Safari'
    elif 'Edge' in user_agent:
        browser = 'Edge'
    elif 'MSIE' in user_agent or 'Trident' in user_agent:
        browser = 'Internet Explorer'

    return device, browser

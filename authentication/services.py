"""
Authentication Service Layer for CloudSec.

Separates all business logic from views. Views should call service
methods; services interact with models, ML, and utilities.
"""
import logging
from django.utils import timezone
from django.contrib.auth import login, logout
from django.conf import settings

from .models import CustomUser, OTPVerification, LoginHistory
from .utils import create_otp, send_otp_email, verify_otp, get_client_ip, get_device_info
from audit.models import AuditLog, SecurityEvent

logger = logging.getLogger(__name__)


class AuthenticationService:
    """
    Central service for all authentication-related operations.
    Handles login flow, OTP verification, registration, and lockout.
    """

    @staticmethod
    def get_user_by_identifier(identifier: str):
        """
        Look up a user by username or email.
        Returns the user object or None.
        """
        try:
            return CustomUser.objects.get(username=identifier)
        except CustomUser.DoesNotExist:
            pass
        try:
            return CustomUser.objects.get(email=identifier)
        except CustomUser.DoesNotExist:
            return None

    @staticmethod
    def record_failed_login(user, request, ip_address: str, device_type: str, browser: str):
        """Record a failed login attempt and check for brute-force escalation."""
        if user:
            user.increment_failed_login()
            LoginHistory.objects.create(
                user=user,
                ip_address=ip_address,
                device_type=device_type,
                browser=browser,
                was_successful=False,
                risk_level='high',
                is_suspicious=True,
            )
            # Create security event after threshold
            if user.failed_login_count >= 3:
                SecurityEvent.objects.get_or_create(
                    user=user,
                    event_type='multiple_failures',
                    is_resolved=False,
                    defaults={
                        'description': (
                            f'Multiple failed login attempts ({user.failed_login_count}) '
                            f'from IP {ip_address}'
                        ),
                        'ip_address': ip_address,
                        'risk_score': min(user.failed_login_count * 0.15, 1.0),
                    }
                )
            AuditLog.objects.create(
                user=user,
                action='login_failed',
                description=f'Failed login attempt from {ip_address}',
                ip_address=ip_address,
                severity='medium' if user.failed_login_count < 3 else 'high',
            )

    @staticmethod
    def record_successful_login(
        user, request, ip_address: str,
        device_type: str, browser: str,
        risk_score: float = 0.0, risk_level: str = 'low'
    ):
        """Record a successful login in history and audit log."""
        LoginHistory.objects.create(
            user=user,
            ip_address=ip_address,
            device_type=device_type,
            browser=browser,
            was_successful=True,
            risk_score=risk_score,
            risk_level=risk_level,
            is_suspicious=(risk_score >= 0.7),
        )
        AuditLog.objects.create(
            user=user,
            action='login_success',
            description=f'Successful MFA login from {ip_address}',
            ip_address=ip_address,
            severity='low',
        )

    @staticmethod
    def initiate_otp_flow(user, request, risk_score: float, risk_level: str,
                          ip_address: str, device_type: str, browser: str):
        """
        Create OTP, send via email, and store metadata in session.
        Adaptive MFA: sets the required verification level based on risk_score.
        
        Risk levels:
          Low  (< 0.4): Password + OTP
          Med  (0.4-0.7): Password + OTP + Security question  
          High (>= 0.7): Password + OTP + Admin approval
        """
        otp_obj = create_otp(user, purpose='login')
        email_sent = send_otp_email(user, otp_obj.otp_code, purpose='login')

        if not email_sent:
            logger.warning(f"OTP email failed for user {user.username}. Check email settings.")

        # Store metadata for OTP verification view
        request.session['verification_user_id'] = str(user.id)
        request.session['verification_purpose'] = 'login'
        request.session['login_risk_score'] = risk_score
        request.session['login_risk_level'] = risk_level
        request.session['login_ip'] = ip_address
        request.session['login_device'] = device_type
        request.session['login_browser'] = browser

        # Adaptive MFA level
        if risk_score >= 0.7:
            request.session['mfa_level'] = 'high'      # OTP + Admin approval
        elif risk_score >= 0.4:
            request.session['mfa_level'] = 'medium'    # OTP + Security question
        else:
            request.session['mfa_level'] = 'low'       # OTP only

        AuditLog.objects.create(
            user=user,
            action='otp_sent',
            description=f'OTP sent to {user.email} — Risk: {risk_level} ({risk_score:.2f})',
            ip_address=ip_address,
            severity='low',
        )
        return otp_obj

    @staticmethod
    def complete_login(user, request):
        """
        Finalise a verified login: call Django login(), set session flags,
        update last_login_ip, and reset failed-login counter.
        """
        ip_address = request.session.get('login_ip', get_client_ip(request))
        risk_score = request.session.get('login_risk_score', 0.0)
        risk_level = request.session.get('login_risk_level', 'low')
        device = request.session.get('login_device', 'Unknown')
        browser = request.session.get('login_browser', 'Unknown')

        user.reset_failed_login()
        user.last_login_ip = ip_address
        user.save(update_fields=['failed_login_count', 'account_locked_until', 'last_login_ip'])

        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        request.session['mfa_verified'] = True

        AuthenticationService.record_successful_login(
            user, request, ip_address, device, browser, risk_score, risk_level
        )

        # Clear MFA session keys
        for key in [
            'verification_user_id', 'verification_purpose',
            'login_risk_score', 'login_risk_level',
            'login_ip', 'login_device', 'login_browser', 'mfa_level',
            'security_question_verified', 'login_user_id',
        ]:
            request.session.pop(key, None)

    @staticmethod
    def register_user(form):
        """
        Create a new user from a validated RegistrationForm.
        Sets status to pending email verification.
        """
        user = form.save(commit=False)
        user.status = 'active'   # Will move to 'pending' when email verification is enforced
        user.role = 'user'
        user.is_active = True
        user.email_verified = False
        user.save()
        logger.info(f"New user registered: {user.username} ({user.email})")
        return user

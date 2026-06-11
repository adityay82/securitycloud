"""
Authentication views for CloudSec.

All views are Class-Based for consistency and reusability.
Business logic is delegated to AuthenticationService.

Critical security fixes applied:
  - OTP bypass REMOVED — MFA is mandatory for every login
  - demo_otp session variable REMOVED — OTP is delivered by email only
  - email_verified auto-bypass REMOVED
  - logout requires POST
  - resend_otp no longer requires @login_required (user not logged in yet)
  - get_device_info() called once, result reused
"""
import time
import logging

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.utils import timezone
from django.http import JsonResponse
from django.views import View
from django.views.decorators.http import require_POST
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit

from .models import CustomUser, OTPVerification, LoginHistory
from .forms import (
    RegistrationForm, LoginForm, OTPForm,
    ForgotPasswordForm, ResetPasswordForm, ProfileUpdateForm,
    SecurityQuestionForm,
)
from .utils import (
    create_otp, send_otp_email, verify_otp,
    get_client_ip, get_device_info,
)
from .services import AuthenticationService
from ml_module.predictor import predict_login_risk
from audit.models import AuditLog

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

class RegisterView(View):
    """User registration — creates account, triggers email OTP verification."""

    template_name = 'authentication/register.html'

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard:index')
        return render(request, self.template_name, {
            'form': RegistrationForm(),
            'page_title': 'Create Account',
        })

    def post(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard:index')

        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = AuthenticationService.register_user(form)

            # Send email verification OTP
            otp_obj = create_otp(user, purpose='email')
            email_sent = send_otp_email(user, otp_obj.otp_code, purpose='email')

            request.session['verification_user_id'] = str(user.id)
            request.session['verification_purpose'] = 'email'

            if email_sent:
                messages.success(
                    request,
                    f'Account created! An OTP has been sent to {user.email}. '
                    f'Please verify your email to activate your account.'
                )
            else:
                messages.warning(
                    request,
                    'Account created! Email delivery failed — check your email configuration. '
                    'Contact an admin to manually verify your account.'
                )
            return redirect('authentication:verify_otp')
        else:
            messages.error(request, 'Please fix the errors below.')

        return render(request, self.template_name, {
            'form': form,
            'page_title': 'Create Account',
        })


# ---------------------------------------------------------------------------
# Login — Level 1: Credentials
# ---------------------------------------------------------------------------

@method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True), name='dispatch')
class LoginView(View):
    """
    MFA Login — Step 1: Verify credentials.
    On success, always redirects to OTP verification (no bypass).
    Adaptive MFA level is determined by ML risk score.
    """

    template_name = 'authentication/login.html'

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard:index')
        return render(request, self.template_name, {
            'form': LoginForm(),
            'page_title': 'Sign In',
        })

    def post(self, request):
        if request.user.is_authenticated:
            return redirect('dashboard:index')

        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        ip_address = get_client_ip(request)

        # Look up user
        user = AuthenticationService.get_user_by_identifier(username)

        # Account lockout check
        if user and user.is_locked():
            remaining = user.account_locked_until - timezone.now()
            minutes = int(remaining.total_seconds() // 60) + 1
            messages.error(
                request,
                f'Account temporarily locked due to multiple failed attempts. '
                f'Try again in {minutes} minute(s).'
            )
            AuditLog.objects.create(
                user=user, action='login_failed',
                description=f'Login attempted while account locked — IP: {ip_address}',
                ip_address=ip_address, severity='high',
            )
            return render(request, self.template_name, {
                'form': LoginForm(),
                'page_title': 'Sign In',
            })

        # Credential check
        if user and user.check_password(password):
            # Account status checks
            if not user.email_verified:
                messages.warning(
                    request,
                    'Please verify your email address before logging in. '
                    'Check your inbox for the OTP.'
                )
                # Re-send verification OTP
                otp_obj = create_otp(user, purpose='email')
                send_otp_email(user, otp_obj.otp_code, purpose='email')
                request.session['verification_user_id'] = str(user.id)
                request.session['verification_purpose'] = 'email'
                return redirect('authentication:verify_otp')

            if user.status == 'pending':
                messages.warning(
                    request,
                    'Your account is pending administrator approval. '
                    'You will be notified once approved.'
                )
                return render(request, self.template_name, {
                    'form': LoginForm(),
                    'page_title': 'Sign In',
                })

            if user.status == 'suspended':
                messages.error(
                    request,
                    'Your account has been suspended. Please contact support.'
                )
                AuditLog.objects.create(
                    user=user, action='login_failed',
                    description=f'Suspended account login attempt from {ip_address}',
                    ip_address=ip_address, severity='high',
                )
                return render(request, self.template_name, {
                    'form': LoginForm(),
                    'page_title': 'Sign In',
                })

            # ── ML Risk Assessment ──────────────────────────────────────
            device_type, browser = get_device_info(request)

            login_features = {
                'hour': timezone.now().hour,
                'ip_address': ip_address,
                'device_type': device_type,
                'browser': browser,
                'failed_attempts': user.failed_login_count,
                'location': 'Unknown',
                'day_of_week': timezone.now().weekday(),
            }

            risk_result = predict_login_risk(login_features, user)
            risk_score = risk_result.get('risk_score', 0.0)
            risk_level = risk_result.get('risk_level', 'low')

            # ── Initiate OTP flow (MANDATORY — no bypass) ───────────────
            AuthenticationService.initiate_otp_flow(
                user, request, risk_score, risk_level,
                ip_address, device_type, browser
            )

            mfa_level = request.session.get('mfa_level', 'low')
            level_messages = {
                'low': 'An OTP has been sent to your registered email address.',
                'medium': 'An OTP has been sent. Additional verification required due to elevated risk.',
                'high': (
                    'High-risk login detected! An OTP has been sent. '
                    'Admin approval may be required.'
                ),
            }
            messages.info(request, level_messages.get(mfa_level, level_messages['low']))
            return redirect('authentication:verify_otp')

        else:
            # Failed login
            device_type, browser = get_device_info(request)

            # Progressive delay (exponential backoff)
            failed_count = user.failed_login_count if user else 0
            if failed_count > 0:
                delay = min(2 ** (failed_count - 1), 16)  # Max 16s
                time.sleep(delay)

            AuthenticationService.record_failed_login(
                user, request, ip_address, device_type, browser
            )
            messages.error(request, 'Invalid username or password.')

        return render(request, self.template_name, {
            'form': LoginForm(),
            'page_title': 'Sign In',
        })


# ---------------------------------------------------------------------------
# OTP Verification — Level 2 (and 2.5 for security question)
# ---------------------------------------------------------------------------

class VerifyOTPView(View):
    """
    MFA Step 2: OTP verification.
    Handles login, email verification, and password reset flows.
    After OTP, may redirect to security question (medium risk) or
    flag for admin review (high risk).
    """

    template_name = 'authentication/verify_otp.html'

    def _get_session_user(self, request):
        user_id = request.session.get('verification_user_id')
        if not user_id:
            return None
        try:
            return CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return None

    def get(self, request):
        user = self._get_session_user(request)
        purpose = request.session.get('verification_purpose', 'login')
        mfa_level = request.session.get('mfa_level', 'low')

        if not user:
            messages.error(request, 'Session expired. Please login again.')
            return redirect('authentication:login')

        return render(request, self.template_name, {
            'form': OTPForm(),
            'user': user,
            'purpose': purpose,
            'mfa_level': mfa_level,
            'page_title': 'Two-Factor Verification',
        })

    def post(self, request):
        user = self._get_session_user(request)
        purpose = request.session.get('verification_purpose', 'login')
        mfa_level = request.session.get('mfa_level', 'low')

        if not user:
            messages.error(request, 'Session expired. Please login again.')
            return redirect('authentication:login')

        form = OTPForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp_code']
            is_valid, message = verify_otp(user, otp_code, purpose)

            if is_valid:
                AuditLog.objects.create(
                    user=user, action='otp_verified',
                    description=f'OTP verified for {purpose}',
                    ip_address=get_client_ip(request), severity='low',
                )

                if purpose == 'email':
                    user.email_verified = True
                    user.status = 'active'
                    user.save(update_fields=['email_verified', 'status'])
                    for key in ['verification_user_id', 'verification_purpose']:
                        request.session.pop(key, None)
                    messages.success(
                        request,
                        '✅ Email verified successfully! You can now log in.'
                    )
                    return redirect('authentication:login')

                elif purpose == 'password_reset':
                    request.session['reset_user_id'] = str(user.id)
                    request.session.pop('verification_user_id', None)
                    request.session.pop('verification_purpose', None)
                    return redirect('authentication:reset_password')

                elif purpose in ('login', 'risk_auth'):
                    # Check if additional verification needed
                    if mfa_level == 'medium' and not request.session.get('security_question_verified'):
                        # Redirect to security question step
                        messages.info(
                            request,
                            'OTP verified. Please answer your security question to complete login.'
                        )
                        return redirect('authentication:security_question')
                    elif mfa_level == 'high':
                        # Flag for admin approval
                        self._flag_high_risk_login(user, request)
                        messages.warning(
                            request,
                            '⚠️ High-risk login detected. Your access request has been flagged '
                            'for administrator review. You will be notified once approved.'
                        )
                        for key in ['verification_user_id', 'verification_purpose', 'mfa_level']:
                            request.session.pop(key, None)
                        return redirect('authentication:login')
                    else:
                        # Low risk — complete login
                        AuthenticationService.complete_login(user, request)
                        messages.success(
                            request,
                            f'✅ Welcome back, {user.get_full_name() or user.username}!'
                        )
                        return redirect('dashboard:index')
            else:
                AuditLog.objects.create(
                    user=user, action='otp_failed',
                    description=f'Invalid OTP attempt for {purpose}',
                    ip_address=get_client_ip(request), severity='medium',
                )
                messages.error(request, message)

        return render(request, self.template_name, {
            'form': form,
            'user': user,
            'purpose': purpose,
            'mfa_level': mfa_level,
            'page_title': 'Two-Factor Verification',
        })

    @staticmethod
    def _flag_high_risk_login(user, request):
        """Create a security event for admin review on high-risk login."""
        from audit.models import SecurityEvent
        ip = request.session.get('login_ip', get_client_ip(request))
        risk_score = request.session.get('login_risk_score', 0.9)
        SecurityEvent.objects.create(
            user=user,
            event_type='suspicious_pattern',
            description=(
                f'High-risk login attempt from {ip} — '
                f'Risk score: {risk_score:.2f}. Awaiting admin review.'
            ),
            ip_address=ip,
            risk_score=risk_score,
            is_resolved=False,
        )
        AuditLog.objects.create(
            user=user, action='suspicious_login_detected',
            description=f'High-risk login flagged for admin review — IP: {ip}',
            ip_address=ip, severity='critical',
        )


# ---------------------------------------------------------------------------
# Security Question — Medium-risk MFA step
# ---------------------------------------------------------------------------

class SecurityQuestionView(View):
    """MFA Step 2.5 for medium-risk logins: verify security question answer."""

    template_name = 'authentication/security_question.html'

    def _get_session_user(self, request):
        user_id = request.session.get('verification_user_id')
        if not user_id:
            return None
        try:
            return CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return None

    def get(self, request):
        user = self._get_session_user(request)
        if not user:
            messages.error(request, 'Session expired. Please login again.')
            return redirect('authentication:login')
        if not hasattr(user, 'security_question') or not user.security_question:
            # No security question set — skip this step and complete login
            request.session['security_question_verified'] = True
            AuthenticationService.complete_login(user, request)
            messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')
            return redirect('dashboard:index')
        return render(request, self.template_name, {
            'user': user,
            'question': user.security_question,
            'page_title': 'Security Question',
        })

    def post(self, request):
        user = self._get_session_user(request)
        if not user:
            messages.error(request, 'Session expired.')
            return redirect('authentication:login')

        answer = request.POST.get('answer', '').strip().lower()
        correct = user.security_answer.strip().lower() if user.security_answer else ''

        if answer == correct:
            request.session['security_question_verified'] = True
            AuthenticationService.complete_login(user, request)
            messages.success(request, f'✅ Welcome back, {user.get_full_name() or user.username}!')
            return redirect('dashboard:index')
        else:
            messages.error(request, 'Incorrect answer. Please try again.')
            AuditLog.objects.create(
                user=user, action='otp_failed',
                description='Security question answered incorrectly',
                ip_address=get_client_ip(request), severity='medium',
            )
        return render(request, self.template_name, {
            'user': user,
            'question': user.security_question,
            'page_title': 'Security Question',
        })


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

class LogoutView(LoginRequiredMixin, View):
    """Secure logout — POST only (CSRF protected)."""

    @method_decorator(require_POST)
    def post(self, request):
        AuditLog.objects.create(
            user=request.user, action='logout',
            description='User logged out',
            ip_address=get_client_ip(request), severity='low',
        )
        logout(request)
        messages.success(request, 'You have been logged out securely.')
        return redirect('authentication:login')

    def get(self, request):
        # GET requests to logout are not allowed — show warning
        messages.warning(request, 'Please use the logout button to sign out securely.')
        return redirect('dashboard:index')


# ---------------------------------------------------------------------------
# Forgot Password
# ---------------------------------------------------------------------------

class ForgotPasswordView(View):
    """Forgot password — sends reset OTP to registered email."""

    template_name = 'authentication/forgot_password.html'

    def get(self, request):
        return render(request, self.template_name, {
            'form': ForgotPasswordForm(),
            'page_title': 'Forgot Password',
        })

    def post(self, request):
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = CustomUser.objects.get(email=email)
                otp_obj = create_otp(user, purpose='password_reset')
                send_otp_email(user, otp_obj.otp_code, purpose='password_reset')
                request.session['verification_user_id'] = str(user.id)
                request.session['verification_purpose'] = 'password_reset'
                messages.success(
                    request,
                    f'Password reset OTP sent to {email}. Check your inbox.'
                )
                return redirect('authentication:verify_otp')
            except CustomUser.DoesNotExist:
                # Don't reveal whether email exists (anti-enumeration)
                messages.success(
                    request,
                    'If an account with that email exists, an OTP has been sent.'
                )
        return render(request, self.template_name, {
            'form': form,
            'page_title': 'Forgot Password',
        })


# ---------------------------------------------------------------------------
# Reset Password
# ---------------------------------------------------------------------------

class ResetPasswordView(View):
    """Reset password after OTP verification."""

    template_name = 'authentication/reset_password.html'

    def get(self, request):
        if not request.session.get('reset_user_id'):
            return redirect('authentication:forgot_password')
        return render(request, self.template_name, {
            'form': ResetPasswordForm(),
            'page_title': 'Reset Password',
        })

    def post(self, request):
        user_id = request.session.get('reset_user_id')
        if not user_id:
            return redirect('authentication:forgot_password')

        user = get_object_or_404(CustomUser, id=user_id)
        form = ResetPasswordForm(request.POST)

        if form.is_valid():
            user.set_password(form.cleaned_data['new_password'])
            user.save()
            request.session.pop('reset_user_id', None)
            AuditLog.objects.create(
                user=user, action='password_reset',
                description='Password reset successfully via OTP',
                ip_address=get_client_ip(request), severity='medium',
            )
            messages.success(
                request,
                '✅ Password reset successfully. Please log in with your new password.'
            )
            return redirect('authentication:login')

        return render(request, self.template_name, {
            'form': form,
            'page_title': 'Reset Password',
        })


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

class ProfileView(LoginRequiredMixin, View):
    """User profile management."""

    template_name = 'authentication/profile.html'

    def get(self, request):
        login_history = LoginHistory.objects.filter(
            user=request.user
        ).order_by('-login_time')[:10]
        return render(request, self.template_name, {
            'form': ProfileUpdateForm(instance=request.user),
            'login_history': login_history,
            'page_title': 'My Profile',
        })

    def post(self, request):
        form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            AuditLog.objects.create(
                user=request.user, action='profile_updated',
                description='Profile updated',
                ip_address=get_client_ip(request), severity='low',
            )
            messages.success(request, 'Profile updated successfully.')
            return redirect('authentication:profile')
        else:
            messages.error(request, 'Please fix the errors below.')

        login_history = LoginHistory.objects.filter(
            user=request.user
        ).order_by('-login_time')[:10]
        return render(request, self.template_name, {
            'form': form,
            'login_history': login_history,
            'page_title': 'My Profile',
        })


# ---------------------------------------------------------------------------
# Resend OTP (AJAX)
# ---------------------------------------------------------------------------

class ResendOTPView(View):
    """Resend OTP via AJAX — does NOT require login (user is in MFA flow)."""

    def post(self, request):
        # Rate-limit: only allow resend if session is valid
        user_id = request.session.get('verification_user_id')
        purpose = request.session.get('verification_purpose', 'login')

        if not user_id:
            return JsonResponse({'success': False, 'message': 'Session expired.'}, status=400)

        try:
            user = CustomUser.objects.get(id=user_id)
            otp_obj = create_otp(user, purpose=purpose)
            email_sent = send_otp_email(user, otp_obj.otp_code, purpose=purpose)
            if email_sent:
                AuditLog.objects.create(
                    user=user, action='otp_sent',
                    description=f'OTP resent for {purpose}',
                    ip_address=get_client_ip(request), severity='low',
                )
                return JsonResponse({'success': True, 'message': 'OTP resent to your email.'})
            else:
                return JsonResponse(
                    {'success': False, 'message': 'Email delivery failed. Check console output.'},
                    status=500
                )
        except CustomUser.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'User not found.'}, status=404)

    def get(self, request):
        return JsonResponse({'success': False, 'message': 'POST request required.'}, status=405)


# ---------------------------------------------------------------------------
# Convenience function-based wrappers (for URL pattern compatibility)
# ---------------------------------------------------------------------------

register_view = RegisterView.as_view()
login_view = LoginView.as_view()
verify_otp_view = VerifyOTPView.as_view()
security_question_view = SecurityQuestionView.as_view()
logout_view = LogoutView.as_view()
forgot_password_view = ForgotPasswordView.as_view()
reset_password_view = ResetPasswordView.as_view()
profile_view = ProfileView.as_view()
resend_otp_view = ResendOTPView.as_view()

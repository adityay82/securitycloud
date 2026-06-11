"""
Reusable authentication decorators for CloudSec.
Use these in place of ad-hoc inline permission checks in views.
"""
from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages


def admin_required(view_func):
    """
    Decorator that restricts access to admin users only.
    Redirects non-admins to the dashboard with an error message.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('authentication:login')
        if request.user.role != 'admin':
            messages.error(request, 'Access denied. Administrator privileges required.')
            return redirect('dashboard:index')
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def active_user_required(view_func):
    """
    Decorator that ensures the user's account is active (not pending/suspended).
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('authentication:login')
        if request.user.status != 'active':
            messages.error(request, 'Your account is not active. Please contact support.')
            return redirect('authentication:login')
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def mfa_verified_required(view_func):
    """
    Decorator that ensures the user completed MFA verification.
    Checks session for 'mfa_verified' flag.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('authentication:login')
        if not request.session.get('mfa_verified', False):
            messages.warning(request, 'Please complete two-factor verification.')
            return redirect('authentication:login')
        return view_func(request, *args, **kwargs)
    return _wrapped_view

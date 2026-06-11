"""
Custom DRF permissions for CloudSec REST API.
"""
from rest_framework.permissions import BasePermission


class IsAdminUser(BasePermission):
    """Allow access only to admin-role users."""
    message = 'Administrator privileges required.'

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.role == 'admin'
        )


class IsActiveUser(BasePermission):
    """Allow access only to active (non-suspended, non-pending) users."""
    message = 'Your account is not active.'

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.status == 'active'
        )


class IsFileOwner(BasePermission):
    """Allow access to file only by its owner (or admin)."""
    message = 'You do not have permission to access this file.'

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user or request.user.role == 'admin'

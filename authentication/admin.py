"""
Enhanced Django admin registrations for CloudSec.
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, OTPVerification, LoginHistory


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = [
        'username', 'email', 'role', 'status',
        'email_verified', 'failed_login_count', 'cumulative_risk_score', 'created_at'
    ]
    list_filter = ['role', 'status', 'email_verified', 'two_factor_enabled']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering = ['-created_at']

    fieldsets = UserAdmin.fieldsets + (
        ('Security Profile', {
            'fields': (
                'role', 'status', 'phone',
                'email_verified', 'two_factor_enabled',
                'failed_login_count', 'account_locked_until', 'last_login_ip',
            )
        }),
        ('Risk Assessment', {
            'fields': ('cumulative_risk_score', 'total_logins', 'total_suspicious_logins')
        }),
        ('Security Question (Adaptive MFA)', {
            'fields': ('security_question', 'security_answer')
        }),
    )

    actions = ['activate_users', 'suspend_users', 'reset_lockout']

    def activate_users(self, request, queryset):
        updated = queryset.update(status='active', is_active=True)
        self.message_user(request, f'{updated} users activated.')
    activate_users.short_description = 'Activate selected users'

    def suspend_users(self, request, queryset):
        updated = queryset.update(status='suspended', is_active=False)
        self.message_user(request, f'{updated} users suspended.')
    suspend_users.short_description = 'Suspend selected users'

    def reset_lockout(self, request, queryset):
        count = 0
        for user in queryset:
            user.reset_failed_login()
            count += 1
        self.message_user(request, f'Lockout reset for {count} users.')
    reset_lockout.short_description = 'Reset lockout for selected users'


@admin.register(OTPVerification)
class OTPVerificationAdmin(admin.ModelAdmin):
    list_display = ['user', 'purpose', 'is_used', 'created_at', 'expires_at', 'attempts']
    list_filter = ['purpose', 'is_used']
    search_fields = ['user__username', 'user__email']
    ordering = ['-created_at']
    readonly_fields = ['otp_code']  # Prevent accidental display in forms


@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'login_time', 'ip_address', 'device_type', 'browser',
        'was_successful', 'risk_level', 'risk_score', 'is_suspicious'
    ]
    list_filter = ['was_successful', 'risk_level', 'is_suspicious', 'device_type']
    search_fields = ['user__username', 'ip_address']
    ordering = ['-login_time']
    date_hierarchy = 'login_time'
    readonly_fields = ['login_time']

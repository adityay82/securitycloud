"""
Dashboard views — CBV-based with threat intelligence integration.
"""
import logging
from datetime import timedelta

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.http import JsonResponse
from django.views import View
from django.utils import timezone
from django.db.models import Avg, Count, Sum

from authentication.models import CustomUser, LoginHistory
from encryption.models import EncryptedFile
from audit.models import AuditLog, SecurityEvent
from audit.intrusion_detection import IntrusionDetectionService
from authentication.utils import get_client_ip

logger = logging.getLogger(__name__)


class DashboardIndexView(LoginRequiredMixin, View):
    """Main dashboard — routes to admin or user view based on role."""

    def get(self, request):
        if request.user.role == 'admin':
            return AdminDashboardView().get(request)
        return UserDashboardView().get(request)


class AdminDashboardView(LoginRequiredMixin, View):
    """Admin security dashboard with full statistics and threat intelligence."""

    template_name = 'dashboard/admin_dashboard.html'

    def get(self, request):
        if request.user.role != 'admin':
            return redirect('dashboard:index')

        now = timezone.now()
        last_7d = now - timedelta(days=7)
        last_24h = now - timedelta(hours=24)

        # ── User Statistics ───────────────────────────────────────────
        total_users = CustomUser.objects.filter(role='user').count()
        active_users = CustomUser.objects.filter(role='user', status='active').count()
        pending_users = CustomUser.objects.filter(status='pending').count()
        suspended_users = CustomUser.objects.filter(status='suspended').count()

        # ── File Statistics ───────────────────────────────────────────
        total_files = EncryptedFile.objects.filter(is_deleted=False).count()
        encrypted_files = EncryptedFile.objects.filter(
            status='encrypted', is_deleted=False
        ).count()
        file_agg = EncryptedFile.objects.filter(is_deleted=False).aggregate(
            avg_enc_time=Avg('encryption_time'),
            total_size=Sum('original_size'),
        )

        # ── Login Statistics ──────────────────────────────────────────
        total_logins = LoginHistory.objects.filter(login_time__gte=last_7d).count()
        successful_logins = LoginHistory.objects.filter(
            login_time__gte=last_7d, was_successful=True
        ).count()
        suspicious_logins = LoginHistory.objects.filter(
            login_time__gte=last_7d, is_suspicious=True
        ).count()
        failed_logins = LoginHistory.objects.filter(
            login_time__gte=last_7d, was_successful=False
        ).count()

        # ── Security Events ───────────────────────────────────────────
        unresolved_events = SecurityEvent.objects.filter(is_resolved=False).count()
        high_risk_events = AuditLog.objects.filter(
            severity__in=['high', 'critical']
        ).count()

        # ── IDS Threat Summary ────────────────────────────────────────
        threat_summary = IntrusionDetectionService.get_threat_summary()

        # ── Risk Distribution ─────────────────────────────────────────
        risk_dist = {
            'low': LoginHistory.objects.filter(
                login_time__gte=last_7d, risk_level='low'
            ).count(),
            'medium': LoginHistory.objects.filter(
                login_time__gte=last_7d, risk_level='medium'
            ).count(),
            'high': LoginHistory.objects.filter(
                login_time__gte=last_7d, risk_level='high'
            ).count(),
        }

        # ── Encryption Distribution ───────────────────────────────────
        # NOTE: keys use no hyphens — Django templates can't access 'AES-128' as a variable
        enc_dist = {
            'aes128': EncryptedFile.objects.filter(
                is_deleted=False, encryption_type='AES-128'
            ).count(),
            'aes192': EncryptedFile.objects.filter(
                is_deleted=False, encryption_type='AES-192'
            ).count(),
            'aes256': EncryptedFile.objects.filter(
                is_deleted=False, encryption_type='AES-256'
            ).count(),
        }

        # ── Recent Activity ───────────────────────────────────────────
        recent_logs = AuditLog.objects.select_related('user').all()[:15]
        recent_security_events = SecurityEvent.objects.select_related(
            'user'
        ).filter(is_resolved=False)[:10]
        pending_approvals = CustomUser.objects.filter(status='pending').order_by('-created_at')

        # ── Security Score (0–100) ────────────────────────────────────
        # Simple heuristic: penalise for unresolved events and suspicious logins
        base_score = 100
        if total_logins > 0:
            suspicious_ratio = suspicious_logins / total_logins
            base_score -= int(suspicious_ratio * 30)
        base_score -= min(unresolved_events * 5, 30)
        security_score = max(base_score, 0)

        context = {
            'total_users': total_users,
            'active_users': active_users,
            'pending_users': pending_users,
            'suspended_users': suspended_users,
            'total_files': total_files,
            'encrypted_files': encrypted_files,
            'total_logins': total_logins,
            'successful_logins': successful_logins,
            'suspicious_logins': suspicious_logins,
            'failed_logins': failed_logins,
            'unresolved_events': unresolved_events,
            'high_risk_events': high_risk_events,
            'threat_summary': threat_summary,
            'risk_dist': risk_dist,
            'enc_dist': enc_dist,
            'recent_logs': recent_logs,
            'recent_security_events': recent_security_events,
            'pending_approvals': pending_approvals,
            'security_score': security_score,
            'avg_enc_time': round(file_agg['avg_enc_time'] or 0, 2),
            'total_size_gb': round((file_agg['total_size'] or 0) / (1024**3), 3),
            'is_admin': True,
            'page_title': 'Admin Security Dashboard',
        }
        return render(request, self.template_name, context)


class UserDashboardView(LoginRequiredMixin, View):
    """User-facing personal security dashboard."""

    template_name = 'dashboard/user_dashboard.html'

    def get(self, request):
        user = request.user
        my_files = EncryptedFile.objects.filter(user=user, is_deleted=False)
        my_logs = AuditLog.objects.filter(user=user).select_related('user')[:15]
        # CRITICAL: filter BEFORE slice to avoid TypeError
        all_logins_qs = LoginHistory.objects.filter(user=user).order_by('-login_time')
        my_logins = all_logins_qs[:10]
        last_suspicious = LoginHistory.objects.filter(
            user=user, is_suspicious=True
        ).first()

        # User risk profile — use the unsliced queryset for aggregation
        avg_risk = all_logins_qs[:20].aggregate(avg=Avg('risk_score'))['avg'] or 0.0

        # Apply filters BEFORE slicing
        risk_dist = {
            'low': all_logins_qs.filter(risk_level='low').count(),
            'medium': all_logins_qs.filter(risk_level='medium').count(),
            'high': all_logins_qs.filter(risk_level='high').count(),
        }

        context = {
            'my_files': my_files.count(),
            'encrypted_files': my_files.filter(status='encrypted').count(),
            'aes256_files': my_files.filter(encryption_type='AES-256').count(),
            'my_logs': my_logs,
            'my_logins': my_logins,
            'last_suspicious': last_suspicious,
            'avg_risk_score': round(avg_risk, 3),
            'risk_label': user.get_risk_label(),
            'risk_dist': risk_dist,
            'is_admin': False,
            'page_title': 'My Security Dashboard',
        }
        return render(request, self.template_name, context)


class ApproveUserView(LoginRequiredMixin, View):
    """Admin: Approve a pending user."""

    def post(self, request, user_id):
        if request.user.role != 'admin':
            return redirect('dashboard:index')
        try:
            target = CustomUser.objects.get(id=user_id, status='pending')
            target.status = 'active'
            target.is_active = True
            target.save(update_fields=['status', 'is_active'])
            AuditLog.objects.create(
                user=request.user, action='user_approved',
                description=f'Approved user: {target.username}',
                ip_address=get_client_ip(request), severity='medium',
            )
            messages.success(request, f'✅ User {target.username} approved.')
        except CustomUser.DoesNotExist:
            messages.error(request, 'User not found.')
        return redirect('dashboard:index')

    def get(self, request, user_id):
        return redirect('dashboard:index')


class SuspendUserView(LoginRequiredMixin, View):
    """Admin: Suspend a user."""

    def post(self, request, user_id):
        if request.user.role != 'admin':
            return redirect('dashboard:index')
        try:
            target = CustomUser.objects.get(id=user_id)
            if target == request.user:
                messages.error(request, 'You cannot suspend your own account.')
                return redirect('dashboard:users')
            target.status = 'suspended'
            target.is_active = False
            target.save(update_fields=['status', 'is_active'])
            AuditLog.objects.create(
                user=request.user, action='user_suspended',
                description=f'Suspended user: {target.username}',
                ip_address=get_client_ip(request), severity='high',
            )
            messages.success(request, f'User {target.username} suspended.')
        except CustomUser.DoesNotExist:
            messages.error(request, 'User not found.')
        return redirect('dashboard:users')

    def get(self, request, user_id):
        return redirect('dashboard:users')


class UsersListView(LoginRequiredMixin, View):
    """Admin: List and manage all users."""

    def get(self, request):
        if request.user.role != 'admin':
            messages.error(request, 'Administrator access required.')
            return redirect('dashboard:index')

        users = CustomUser.objects.all().order_by('-created_at').annotate(
            login_count=Count('login_history'),
            file_count=Count('files'),
        )

        # Filter
        status_filter = request.GET.get('status', '')
        role_filter = request.GET.get('role', '')
        if status_filter:
            users = users.filter(status=status_filter)
        if role_filter:
            users = users.filter(role=role_filter)

        return render(request, 'dashboard/users_list.html', {
            'users': users,
            'status_filter': status_filter,
            'role_filter': role_filter,
            'page_title': 'User Management',
        })


class DashboardStatsAPIView(LoginRequiredMixin, View):
    """AJAX: Dashboard statistics for Chart.js (7-day login trend)."""

    def get(self, request):
        now = timezone.now()
        daily_data = []
        for i in range(6, -1, -1):
            day = (now - timedelta(days=i)).date()
            qs = LoginHistory.objects.filter(login_time__date=day)
            if request.user.role != 'admin':
                qs = qs.filter(user=request.user)
            daily_data.append({
                'date': str(day),
                'total': qs.count(),
                'successful': qs.filter(was_successful=True).count(),
                'suspicious': qs.filter(is_suspicious=True).count(),
            })

        return JsonResponse({
            'daily_logins': daily_data,
            'total_users': CustomUser.objects.count(),
            'active_users': CustomUser.objects.filter(status='active').count(),
        })


# URL aliases
index_view = DashboardIndexView.as_view()
admin_dashboard_view = AdminDashboardView.as_view()
user_dashboard_view = UserDashboardView.as_view()
approve_user_view = ApproveUserView.as_view()
suspend_user_view = SuspendUserView.as_view()
users_list_view = UsersListView.as_view()
dashboard_stats_api = DashboardStatsAPIView.as_view()

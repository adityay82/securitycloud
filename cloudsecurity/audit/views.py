"""
Audit views — CBV-based with pagination and fixed queryset ordering.

Critical bug fixed:
  Old code: logs = AuditLog.objects.all()[:200] then logs.filter(...)
  This silently returns ALL records (filter on sliced queryset is ignored in Django).
  Fixed: filter BEFORE slicing.
"""
import csv
import logging
from datetime import timedelta

from django.shortcuts import render, redirect
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views import View
from django.core.paginator import Paginator
from django.utils import timezone
from django.db.models import Count

from .models import AuditLog, SecurityEvent
from authentication.decorators import admin_required
from authentication.utils import get_client_ip

logger = logging.getLogger(__name__)


class AuditLogView(LoginRequiredMixin, View):
    """Paginated audit log view with filtering."""

    template_name = 'audit/logs.html'
    ITEMS_PER_PAGE = 25

    def get(self, request):
        # Build queryset based on role
        if request.user.role == 'admin':
            qs = AuditLog.objects.select_related('user').all()
        else:
            qs = AuditLog.objects.filter(user=request.user)

        # ── Filters (applied BEFORE slicing — fixes critical bug) ──
        severity = request.GET.get('severity', '').strip()
        action = request.GET.get('action', '').strip()
        date_from = request.GET.get('date_from', '').strip()
        date_to = request.GET.get('date_to', '').strip()

        if severity and severity in dict(AuditLog.SEVERITY_CHOICES):
            qs = qs.filter(severity=severity)
        if action:
            qs = qs.filter(action__icontains=action)
        if date_from:
            try:
                qs = qs.filter(timestamp__date__gte=date_from)
            except ValueError:
                pass
        if date_to:
            try:
                qs = qs.filter(timestamp__date__lte=date_to)
            except ValueError:
                pass

        # ── Pagination ──────────────────────────────────────────────
        paginator = Paginator(qs, self.ITEMS_PER_PAGE)
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)

        # Stats for summary cards
        last_7d = timezone.now() - timedelta(days=7)
        if request.user.role == 'admin':
            recent = AuditLog.objects.filter(timestamp__gte=last_7d)
        else:
            recent = AuditLog.objects.filter(user=request.user, timestamp__gte=last_7d)

        stats = {
            'total': qs.count(),
            'critical': recent.filter(severity='critical').count(),
            'high': recent.filter(severity='high').count(),
            'medium': recent.filter(severity='medium').count(),
            'low': recent.filter(severity='low').count(),
        }

        return render(request, self.template_name, {
            'page_obj': page_obj,
            'logs': page_obj,  # backwards compat
            'stats': stats,
            'severity_choices': AuditLog.SEVERITY_CHOICES,
            'current_severity': severity,
            'current_action': action,
            'date_from': date_from,
            'date_to': date_to,
            'page_title': 'Audit Logs',
        })


class SecurityEventsView(LoginRequiredMixin, View):
    """Security events view — admin only."""

    template_name = 'audit/security_events.html'

    def get(self, request):
        if request.user.role != 'admin':
            messages.error(request, 'Administrator access required.')
            return redirect('dashboard:index')

        events = SecurityEvent.objects.select_related('user', 'resolved_by').all()

        # Filter by resolution status
        resolved = request.GET.get('resolved', 'false')
        if resolved == 'true':
            events = events.filter(is_resolved=True)
        else:
            events = events.filter(is_resolved=False)

        paginator = Paginator(events, 20)
        page_obj = paginator.get_page(request.GET.get('page', 1))

        event_type_counts = {
            et: SecurityEvent.objects.filter(event_type=et, is_resolved=False).count()
            for et, _ in SecurityEvent.EVENT_TYPES
        }

        return render(request, self.template_name, {
            'page_obj': page_obj,
            'events': page_obj,
            'event_type_counts': event_type_counts,
            'showing_resolved': resolved == 'true',
            'page_title': 'Security Events & IDS Alerts',
        })

    def post(self, request):
        """Mark a security event as resolved."""
        if request.user.role != 'admin':
            return JsonResponse({'error': 'Unauthorized'}, status=403)

        event_id = request.POST.get('event_id')
        try:
            event = SecurityEvent.objects.get(id=event_id)
            event.is_resolved = True
            event.resolved_by = request.user
            event.resolved_at = timezone.now()
            event.save()
            AuditLog.objects.create(
                user=request.user, action='user_approved',
                description=f'Security event resolved: {event.event_type} — {event.user.username}',
                ip_address=get_client_ip(request), severity='medium',
            )
            return JsonResponse({'success': True})
        except SecurityEvent.DoesNotExist:
            return JsonResponse({'error': 'Event not found.'}, status=404)


class ExportAuditCSVView(LoginRequiredMixin, View):
    """Export audit logs as CSV — compliance export (SOC 2, ISO 27001)."""

    def get(self, request):
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = (
            f'attachment; filename="cloudsec_audit_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        )

        writer = csv.writer(response)
        writer.writerow([
            'Timestamp (UTC)', 'User', 'Action', 'Action Label',
            'Severity', 'IP Address', 'Description'
        ])

        if request.user.role == 'admin':
            logs = AuditLog.objects.select_related('user').all()[:2000]
        else:
            logs = AuditLog.objects.filter(user=request.user)[:500]

        for log in logs:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.user.username if log.user else 'System',
                log.action,
                log.get_action_display(),
                log.get_severity_display(),
                log.ip_address or 'N/A',
                log.description,
            ])

        AuditLog.objects.create(
            user=request.user, action='file_downloaded',
            description=f'Audit log exported as CSV ({logs.count()} records)',
            ip_address=get_client_ip(request), severity='medium',
        )
        return response


class AuditStatsAPIView(LoginRequiredMixin, View):
    """AJAX: Audit statistics for dashboard charts."""

    def get(self, request):
        last_7d = timezone.now() - timedelta(days=7)

        if request.user.role == 'admin':
            base_qs = AuditLog.objects.all()
            recent = base_qs.filter(timestamp__gte=last_7d)
        else:
            base_qs = AuditLog.objects.filter(user=request.user)
            recent = base_qs.filter(timestamp__gte=last_7d)

        severity_counts = {
            'low': recent.filter(severity='low').count(),
            'medium': recent.filter(severity='medium').count(),
            'high': recent.filter(severity='high').count(),
            'critical': recent.filter(severity='critical').count(),
        }

        daily_counts = []
        for i in range(6, -1, -1):
            day = (timezone.now() - timedelta(days=i)).date()
            count = recent.filter(timestamp__date=day).count()
            daily_counts.append({'date': str(day), 'count': count})

        action_counts = list(
            recent.values('action').annotate(count=Count('action')).order_by('-count')[:10]
        )

        return JsonResponse({
            'severity_distribution': severity_counts,
            'daily_activity': daily_counts,
            'top_actions': action_counts,
            'total_events': recent.count(),
            'unresolved_security_events': SecurityEvent.objects.filter(is_resolved=False).count(),
        })


# URL aliases
audit_log_view = AuditLogView.as_view()
security_events_view = SecurityEventsView.as_view()
export_audit_csv = ExportAuditCSVView.as_view()
audit_stats_api = AuditStatsAPIView.as_view()

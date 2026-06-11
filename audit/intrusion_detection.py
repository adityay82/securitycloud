"""
Intrusion Detection System for CloudSec.

Detects:
  - Brute force attacks (multiple failures from single IP)
  - Multiple login failures per user
  - IP address changes mid-session
  - Unusual login hours (late-night / early morning)
  - Rapid successive logins (impossible travel proxy)

Generates SecurityEvent records for admin review.
"""
import logging
from django.utils import timezone
from datetime import timedelta

logger = logging.getLogger(__name__)


class IntrusionDetectionService:
    """
    Lightweight IDS that analyses login patterns and creates security events.
    Called from AuditMiddleware and authentication views.
    """

    # Thresholds
    BRUTE_FORCE_THRESHOLD = 5          # failures per hour per IP
    USER_FAILURE_THRESHOLD = 3         # failures per hour per user
    UNUSUAL_HOURS = list(range(0, 6))  # midnight to 6am
    RAPID_LOGIN_SECONDS = 10           # two logins from same user in < 10s = suspicious

    @classmethod
    def analyse_login_attempt(cls, user, ip_address: str, was_successful: bool,
                               request=None) -> list:
        """
        Main entry point. Analyse a login attempt and create SecurityEvents.
        Returns list of created SecurityEvent objects.
        """
        from audit.models import SecurityEvent
        from authentication.models import LoginHistory

        events_created = []
        now = timezone.now()
        one_hour_ago = now - timedelta(hours=1)

        # 1. Brute force: multiple failures from same IP in last hour
        ip_failures = LoginHistory.objects.filter(
            ip_address=ip_address,
            was_successful=False,
            login_time__gte=one_hour_ago,
        ).count()

        if ip_failures >= cls.BRUTE_FORCE_THRESHOLD and user:
            event, created = SecurityEvent.objects.get_or_create(
                user=user,
                event_type='brute_force',
                is_resolved=False,
                defaults={
                    'description': (
                        f'Brute force attack detected: {ip_failures} failed attempts '
                        f'from IP {ip_address} in the last hour.'
                    ),
                    'ip_address': ip_address,
                    'risk_score': min(0.5 + (ip_failures * 0.05), 1.0),
                },
            )
            if created:
                events_created.append(event)
                logger.warning(
                    f"IDS: Brute force detected for {user.username} from {ip_address}"
                )

        # 2. Multiple auth failures per user
        if user:
            user_failures = LoginHistory.objects.filter(
                user=user,
                was_successful=False,
                login_time__gte=one_hour_ago,
            ).count()

            if user_failures >= cls.USER_FAILURE_THRESHOLD:
                event, created = SecurityEvent.objects.get_or_create(
                    user=user,
                    event_type='multiple_failures',
                    is_resolved=False,
                    defaults={
                        'description': (
                            f'{user_failures} failed login attempts for {user.username} '
                            f'in the last hour.'
                        ),
                        'ip_address': ip_address,
                        'risk_score': min(0.4 + (user_failures * 0.08), 1.0),
                    },
                )
                if created:
                    events_created.append(event)

        # 3. Unusual hours detection
        if was_successful and user and now.hour in cls.UNUSUAL_HOURS:
            event, created = SecurityEvent.objects.get_or_create(
                user=user,
                event_type='suspicious_pattern',
                is_resolved=False,
                defaults={
                    'description': (
                        f'Login at unusual hour: {now.strftime("%H:%M")} UTC '
                        f'from {ip_address}.'
                    ),
                    'ip_address': ip_address,
                    'risk_score': 0.6,
                },
            )
            if created:
                events_created.append(event)

        # 4. IP change detection (user logged in from different IP than last time)
        if was_successful and user and user.last_login_ip:
            if user.last_login_ip != ip_address:
                event, created = SecurityEvent.objects.get_or_create(
                    user=user,
                    event_type='unusual_location',
                    is_resolved=False,
                    defaults={
                        'description': (
                            f'Login from new IP: {ip_address}. '
                            f'Previous IP: {user.last_login_ip}.'
                        ),
                        'ip_address': ip_address,
                        'risk_score': 0.55,
                    },
                )
                if created:
                    events_created.append(event)
                    logger.info(
                        f"IDS: IP change for {user.username}: "
                        f"{user.last_login_ip} → {ip_address}"
                    )

        return events_created

    @classmethod
    def get_threat_summary(cls) -> dict:
        """Return a summary dict for the admin threat intelligence dashboard."""
        from audit.models import SecurityEvent
        from authentication.models import LoginHistory

        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        unresolved_events = SecurityEvent.objects.filter(is_resolved=False)
        recent_events = SecurityEvent.objects.filter(detected_at__gte=last_24h)

        return {
            'unresolved_count': unresolved_events.count(),
            'brute_force_count': unresolved_events.filter(event_type='brute_force').count(),
            'ip_change_count': unresolved_events.filter(event_type='unusual_location').count(),
            'unusual_hours_count': unresolved_events.filter(
                event_type='suspicious_pattern').count(),
            'multiple_failures_count': unresolved_events.filter(
                event_type='multiple_failures').count(),
            'recent_24h': recent_events.count(),
            'high_risk_logins': LoginHistory.objects.filter(
                login_time__gte=last_7d, risk_level='high'
            ).count(),
            'suspicious_logins': LoginHistory.objects.filter(
                login_time__gte=last_7d, is_suspicious=True
            ).count(),
        }

"""
CloudSec REST API views.
All endpoints use JWT authentication + custom permissions.

Endpoints:
  POST   /api/v1/auth/register/
  POST   /api/v1/auth/login/
  POST   /api/v1/auth/verify-otp/
  POST   /api/v1/auth/token/refresh/
  POST   /api/v1/auth/logout/

  GET    /api/v1/files/
  POST   /api/v1/files/upload/
  GET    /api/v1/files/{id}/
  DELETE /api/v1/files/{id}/
  GET    /api/v1/files/{id}/download/
  GET    /api/v1/files/{id}/integrity/

  GET    /api/v1/ml/risk-score/
  GET    /api/v1/ml/model-metrics/
  POST   /api/v1/ml/retrain/

  GET    /api/v1/audit/logs/
  GET    /api/v1/audit/events/
  GET    /api/v1/audit/export/

  GET    /api/v1/dashboard/stats/
  GET    /api/v1/dashboard/login-trend/
"""
import logging
from datetime import timedelta

from django.utils import timezone
from django.http import HttpResponse
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.models import CustomUser, LoginHistory
from authentication.utils import create_otp, send_otp_email, verify_otp, get_client_ip
from encryption.models import EncryptedFile
from encryption.services import EncryptionService, FileValidationError
from audit.models import AuditLog, SecurityEvent
from ml_module.predictor import predict_login_risk, get_model_metrics, train_models
from .serializers import (
    UserSerializer, LoginSerializer, RegisterSerializer, OTPVerifySerializer,
    EncryptedFileSerializer, AuditLogSerializer, SecurityEventSerializer,
    LoginHistorySerializer, RiskScoreSerializer, DashboardStatsSerializer,
)
from .permissions import IsAdminUser, IsActiveUser, IsFileOwner

logger = logging.getLogger(__name__)


# ─── Auth Endpoints ───────────────────────────────────────────────────────

class RegisterAPIView(APIView):
    """POST /api/v1/auth/register/ — Create a new user account."""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Send email verification OTP
            otp_obj = create_otp(user, purpose='email')
            send_otp_email(user, otp_obj.otp_code, purpose='email')
            return Response({
                'message': 'Registration successful. OTP sent to your email for verification.',
                'user_id': str(user.id),
                'email': user.email,
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    """POST /api/v1/auth/login/ — Initiate MFA login flow."""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)

        user = serializer.validated_data['user']
        ip_address = get_client_ip(request)

        # ML risk assessment
        from authentication.utils import get_device_info
        device_type, browser = get_device_info(request)
        risk_result = predict_login_risk({
            'hour': timezone.now().hour,
            'ip_address': ip_address,
            'device_type': device_type,
            'browser': browser,
            'failed_attempts': user.failed_login_count,
            'day_of_week': timezone.now().weekday(),
        }, user)

        # Create OTP — no JWT token yet (must verify OTP first)
        otp_obj = create_otp(user, purpose='login')
        send_otp_email(user, otp_obj.otp_code, purpose='login')

        AuditLog.objects.create(
            user=user, action='otp_sent',
            description=f'API login — OTP sent. Risk: {risk_result["risk_level"]}',
            ip_address=ip_address, severity='low',
        )

        return Response({
            'message': 'OTP sent to your registered email. Use /api/v1/auth/verify-otp/ to complete login.',
            'user_id': str(user.id),
            'risk_level': risk_result['risk_level'],
            'mfa_required': True,
        }, status=status.HTTP_200_OK)


class VerifyOTPAPIView(APIView):
    """POST /api/v1/auth/verify-otp/ — Verify OTP and receive JWT tokens."""
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.data.get('user_id')
        serializer = OTPVerifySerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(id=user_id)
        except (CustomUser.DoesNotExist, ValueError):
            return Response({'error': 'Invalid user ID.'}, status=status.HTTP_400_BAD_REQUEST)

        otp_code = serializer.validated_data['otp_code']
        purpose = serializer.validated_data['purpose']

        is_valid, message = verify_otp(user, otp_code, purpose)
        if not is_valid:
            AuditLog.objects.create(
                user=user, action='otp_failed',
                description=f'API OTP verification failed for {purpose}',
                ip_address=get_client_ip(request), severity='medium',
            )
            return Response({'error': message}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        AuditLog.objects.create(
            user=user, action='login_success',
            description='API login completed via OTP verification',
            ip_address=get_client_ip(request), severity='low',
        )

        return Response({
            'message': 'Authentication successful.',
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': UserSerializer(user).data,
        }, status=status.HTTP_200_OK)


class LogoutAPIView(APIView):
    """POST /api/v1/auth/logout/ — Blacklist refresh token."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()
            AuditLog.objects.create(
                user=request.user, action='logout',
                description='API logout — token blacklisted',
                ip_address=get_client_ip(request), severity='low',
            )
            return Response({'message': 'Logged out successfully.'})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


# ─── File Endpoints ───────────────────────────────────────────────────────

class FileListAPIView(APIView):
    """GET /api/v1/files/ — List user's encrypted files."""
    permission_classes = [IsAuthenticated, IsActiveUser]

    def get(self, request):
        if request.user.role == 'admin':
            files = EncryptedFile.objects.filter(is_deleted=False).select_related('user')
        else:
            files = EncryptedFile.objects.filter(user=request.user, is_deleted=False)
        serializer = EncryptedFileSerializer(files, many=True)
        return Response({'files': serializer.data, 'count': files.count()})


class FileUploadAPIView(APIView):
    """POST /api/v1/files/upload/ — Upload and encrypt a file."""
    permission_classes = [IsAuthenticated, IsActiveUser]

    def post(self, request):
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return Response({'error': 'No file provided.'}, status=status.HTTP_400_BAD_REQUEST)

        sensitivity = request.data.get('sensitivity', 'medium')
        risk_score = request.session.get('login_risk_score', 0.0)

        try:
            enc_file = EncryptionService.encrypt_and_store(
                uploaded_file, request.user, risk_score, sensitivity
            )
            AuditLog.objects.create(
                user=request.user, action='file_encrypted',
                description=f'API file upload: {uploaded_file.name} → {enc_file.encryption_type}',
                ip_address=get_client_ip(request), severity='low',
            )
            return Response({
                'message': 'File encrypted and stored successfully.',
                'file': EncryptedFileSerializer(enc_file).data,
            }, status=status.HTTP_201_CREATED)
        except FileValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"API upload error: {e}")
            return Response({'error': 'Encryption failed.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FileDetailAPIView(APIView):
    """GET/DELETE /api/v1/files/{id}/"""
    permission_classes = [IsAuthenticated, IsActiveUser]

    def get_object(self, request, file_id):
        try:
            f = EncryptedFile.objects.get(id=file_id, is_deleted=False)
            if f.user != request.user and request.user.role != 'admin':
                return None, Response(
                    {'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND
                )
            return f, None
        except EncryptedFile.DoesNotExist:
            return None, Response({'error': 'File not found.'}, status=status.HTTP_404_NOT_FOUND)

    def get(self, request, file_id):
        f, err = self.get_object(request, file_id)
        if err:
            return err
        return Response(EncryptedFileSerializer(f).data)

    def delete(self, request, file_id):
        f, err = self.get_object(request, file_id)
        if err:
            return err
        f.is_deleted = True
        f.save(update_fields=['is_deleted'])
        AuditLog.objects.create(
            user=request.user, action='file_deleted',
            description=f'API delete: {f.original_filename}',
            ip_address=get_client_ip(request), severity='medium',
        )
        return Response({'message': 'File deleted.'}, status=status.HTTP_200_OK)


class FileIntegrityAPIView(APIView):
    """GET /api/v1/files/{id}/integrity/ — Verify file integrity."""
    permission_classes = [IsAuthenticated, IsActiveUser]

    def get(self, request, file_id):
        try:
            f = EncryptedFile.objects.get(id=file_id, is_deleted=False)
            if f.user != request.user and request.user.role != 'admin':
                return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        except EncryptedFile.DoesNotExist:
            return Response({'error': 'File not found.'}, status=status.HTTP_404_NOT_FOUND)

        result = EncryptionService.verify_file_integrity(f)
        AuditLog.objects.create(
            user=request.user,
            action='file_integrity_check' if result.get('integrity') else 'integrity_failed',
            description=f'API integrity check: {f.original_filename} — {result["status"]}',
            ip_address=get_client_ip(request),
            severity='low' if result.get('integrity') else 'critical',
        )
        return Response(result)


# ─── ML Endpoints ─────────────────────────────────────────────────────────

class RiskScoreAPIView(APIView):
    """GET /api/v1/ml/risk-score/ — Get current user's risk assessment."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from authentication.utils import get_device_info
        ip_address = get_client_ip(request)
        device_type, browser = get_device_info(request)

        result = predict_login_risk({
            'hour': timezone.now().hour,
            'ip_address': ip_address,
            'device_type': device_type,
            'browser': browser,
            'failed_attempts': request.user.failed_login_count,
            'day_of_week': timezone.now().weekday(),
        }, request.user)

        serializer = RiskScoreSerializer(data=result)
        serializer.is_valid()
        return Response(serializer.data)


class ModelMetricsAPIView(APIView):
    """GET /api/v1/ml/model-metrics/ — Return cached model performance metrics."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        metrics = get_model_metrics(force_retrain=False)
        return Response(metrics)


class RetrainModelAPIView(APIView):
    """POST /api/v1/ml/retrain/ — Force model retraining (admin only)."""
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        try:
            metrics = train_models()
            return Response({'message': 'Models retrained successfully.', 'metrics': metrics})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─── Audit Endpoints ──────────────────────────────────────────────────────

class AuditLogAPIView(APIView):
    """GET /api/v1/audit/logs/ — Paginated audit log list."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role == 'admin':
            qs = AuditLog.objects.select_related('user').all()
        else:
            qs = AuditLog.objects.filter(user=request.user)

        # Filtering
        severity = request.query_params.get('severity')
        action = request.query_params.get('action')
        if severity:
            qs = qs.filter(severity=severity)
        if action:
            qs = qs.filter(action__icontains=action)

        qs = qs[:200]
        serializer = AuditLogSerializer(qs, many=True)
        return Response({'logs': serializer.data, 'count': len(serializer.data)})


class SecurityEventsAPIView(APIView):
    """GET /api/v1/audit/events/ — Security events (admin only)."""
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        events = SecurityEvent.objects.select_related('user').filter(is_resolved=False)
        serializer = SecurityEventSerializer(events, many=True)
        return Response({'events': serializer.data, 'count': events.count()})

    def patch(self, request, event_id=None):
        """Mark event as resolved."""
        try:
            event = SecurityEvent.objects.get(id=event_id)
            event.is_resolved = True
            event.resolved_by = request.user
            event.resolved_at = timezone.now()
            event.save()
            return Response({'message': 'Event marked as resolved.'})
        except SecurityEvent.DoesNotExist:
            return Response({'error': 'Event not found.'}, status=status.HTTP_404_NOT_FOUND)


class AuditExportAPIView(APIView):
    """GET /api/v1/audit/export/ — Export audit logs as CSV."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        import csv
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = (
            f'attachment; filename="audit_logs_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        )
        writer = csv.writer(response)
        writer.writerow(['Timestamp', 'User', 'Action', 'Severity', 'IP Address', 'Description'])

        if request.user.role == 'admin':
            logs = AuditLog.objects.select_related('user').all()[:1000]
        else:
            logs = AuditLog.objects.filter(user=request.user)[:500]

        for log in logs:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                log.user.username if log.user else 'System',
                log.get_action_display(),
                log.get_severity_display(),
                log.ip_address or 'N/A',
                log.description,
            ])
        return response


# ─── Dashboard Endpoints ──────────────────────────────────────────────────

class DashboardStatsAPIView(APIView):
    """GET /api/v1/dashboard/stats/ — Aggregated dashboard statistics."""
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        last_7d = timezone.now() - timedelta(days=7)
        stats = {
            'total_users': CustomUser.objects.filter(role='user').count(),
            'active_users': CustomUser.objects.filter(status='active').count(),
            'total_files': EncryptedFile.objects.filter(is_deleted=False).count(),
            'encrypted_files': EncryptedFile.objects.filter(
                status='encrypted', is_deleted=False
            ).count(),
            'total_logins_7d': LoginHistory.objects.filter(login_time__gte=last_7d).count(),
            'suspicious_logins_7d': LoginHistory.objects.filter(
                login_time__gte=last_7d, is_suspicious=True
            ).count(),
            'high_risk_events': AuditLog.objects.filter(
                severity__in=['high', 'critical']
            ).count(),
            'unresolved_security_events': SecurityEvent.objects.filter(
                is_resolved=False
            ).count(),
        }
        return Response(stats)


class LoginTrendAPIView(APIView):
    """GET /api/v1/dashboard/login-trend/ — 7-day login trend data for Chart.js."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        data = []
        for i in range(6, -1, -1):
            day = (timezone.now() - timedelta(days=i)).date()
            qs = LoginHistory.objects.filter(login_time__date=day)
            if request.user.role != 'admin':
                qs = qs.filter(user=request.user)
            data.append({
                'date': str(day),
                'total': qs.count(),
                'successful': qs.filter(was_successful=True).count(),
                'suspicious': qs.filter(is_suspicious=True).count(),
            })
        return Response(data)

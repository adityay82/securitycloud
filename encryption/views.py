"""
Encryption views — CBV-based, all logic delegated to EncryptionService.
"""
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from django.views import View
from django.db.models import Avg, Count

from .models import EncryptedFile
from .services import EncryptionService, FileValidationError
from audit.models import AuditLog
from authentication.utils import get_client_ip

logger = logging.getLogger(__name__)


class UploadFileView(LoginRequiredMixin, View):
    """Upload and encrypt a file with adaptive AES selection."""

    def post(self, request):
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            messages.error(request, 'No file selected.')
            return redirect('filemanager:list')

        # Get optional sensitivity level from form
        sensitivity = request.POST.get('sensitivity', 'medium')
        if sensitivity not in ('low', 'medium', 'high', 'critical'):
            sensitivity = 'medium'

        # Get current user's risk score from session
        risk_score = request.session.get('login_risk_score', 0.0)

        try:
            enc_file = EncryptionService.encrypt_and_store(
                uploaded_file, request.user, risk_score, sensitivity
            )
            AuditLog.objects.create(
                user=request.user,
                action='file_encrypted',
                description=(
                    f'File "{uploaded_file.name}" encrypted with '
                    f'{enc_file.encryption_type} in {enc_file.encryption_time:.1f}ms. '
                    f'Sensitivity: {sensitivity}'
                ),
                ip_address=get_client_ip(request),
                severity='low',
            )
            messages.success(
                request,
                f'✅ File encrypted with {enc_file.encryption_type} '
                f'({enc_file.encryption_time:.1f}ms). SHA-256 hash recorded for integrity.'
            )

        except FileValidationError as e:
            AuditLog.objects.create(
                user=request.user,
                action='suspicious_access',
                description=f'File upload validation failed: {str(e)}',
                ip_address=get_client_ip(request),
                severity='high',
            )
            messages.error(request, f'⚠️ Upload rejected: {str(e)}')

        except Exception as e:
            logger.error(f"Upload error for user {request.user.username}: {e}", exc_info=True)
            messages.error(request, 'An unexpected error occurred during encryption.')

        return redirect('filemanager:list')

    def get(self, request):
        return redirect('filemanager:list')


class DownloadEncryptedView(LoginRequiredMixin, View):
    """Download raw encrypted file (without decrypting)."""

    def get(self, request, file_id):
        enc_file = get_object_or_404(
            EncryptedFile, id=file_id, user=request.user, is_deleted=False
        )

        try:
            file_path = enc_file.file_path.path
            import os
            if not os.path.exists(file_path):
                messages.error(request, 'File not found on server.')
                return redirect('filemanager:list')

            with open(file_path, 'rb') as f:
                encrypted_data = f.read()

            AuditLog.objects.create(
                user=request.user, action='file_downloaded',
                description=f'Downloaded encrypted file: {enc_file.original_filename}',
                ip_address=get_client_ip(request), severity='low',
            )

            response = HttpResponse(encrypted_data, content_type='application/octet-stream')
            response['Content-Disposition'] = (
                f'attachment; filename="ENCRYPTED_{enc_file.original_filename}"'
            )
            return response

        except Exception as e:
            logger.error(f"Download error: {e}")
            messages.error(request, 'Download failed.')
            return redirect('filemanager:list')


class DecryptFileView(LoginRequiredMixin, View):
    """Decrypt and download original file with integrity verification."""

    def get(self, request, file_id):
        enc_file = get_object_or_404(
            EncryptedFile, id=file_id, user=request.user, is_deleted=False
        )

        if enc_file.status != 'encrypted':
            messages.error(request, 'File is not in encrypted state.')
            return redirect('filemanager:list')

        try:
            result = EncryptionService.decrypt_for_download(enc_file)
            decrypted_data = result['decrypted_data']
            integrity_ok = result['integrity_ok']

            AuditLog.objects.create(
                user=request.user, action='file_decrypted',
                description=(
                    f'Decrypted "{enc_file.original_filename}". '
                    f'Integrity: {"✅ OK" if integrity_ok else "❌ FAILED"}. '
                    f'Time: {result["decryption_time_ms"]:.1f}ms'
                ),
                ip_address=get_client_ip(request),
                severity='medium' if not integrity_ok else 'low',
            )

            if not integrity_ok:
                messages.warning(
                    request,
                    '⚠️ File integrity check FAILED! The file may have been tampered with. '
                    'Proceeding with caution.'
                )
            else:
                messages.info(
                    request,
                    f'✅ File decrypted and integrity verified in {result["decryption_time_ms"]:.1f}ms.'
                )

            response = HttpResponse(decrypted_data, content_type='application/octet-stream')
            response['Content-Disposition'] = (
                f'attachment; filename="{enc_file.original_filename}"'
            )
            return response

        except FileNotFoundError:
            messages.error(request, 'Encrypted file not found on server.')
            return redirect('filemanager:list')

        except Exception as e:
            AuditLog.objects.create(
                user=request.user, action='decryption_error',
                description=f'Decryption error for {enc_file.original_filename}: {str(e)}',
                ip_address=get_client_ip(request), severity='high',
            )
            logger.error(f"Decryption error: {e}", exc_info=True)
            messages.error(request, 'Decryption failed. File may be corrupted.')
            return redirect('filemanager:list')


class VerifyIntegrityView(LoginRequiredMixin, View):
    """AJAX: Verify file integrity using SHA-256 without serving the file."""

    def get(self, request, file_id):
        enc_file = get_object_or_404(
            EncryptedFile, id=file_id, user=request.user, is_deleted=False
        )
        result = EncryptionService.verify_file_integrity(enc_file)

        # Log integrity check
        action = 'file_integrity_check' if result.get('integrity') else 'integrity_failed'
        severity = 'low' if result.get('integrity') else 'critical'
        AuditLog.objects.create(
            user=request.user, action=action,
            description=(
                f'Integrity check for "{enc_file.original_filename}": '
                f'{result.get("status", "unknown").upper()}'
            ),
            ip_address=get_client_ip(request), severity=severity,
        )

        status_code = 200 if result['status'] in ('ok', 'failed') else 500
        return JsonResponse(result, status=status_code)


class EncryptionStatsAPIView(LoginRequiredMixin, View):
    """API: Return encryption statistics for Chart.js."""

    def get(self, request):
        if request.user.role == 'admin':
            files = EncryptedFile.objects.filter(is_deleted=False)
        else:
            files = EncryptedFile.objects.filter(user=request.user, is_deleted=False)

        # Use DB aggregation (not Python loops)
        enc_dist = {
            'AES-128': files.filter(encryption_type='AES-128').count(),
            'AES-192': files.filter(encryption_type='AES-192').count(),
            'AES-256': files.filter(encryption_type='AES-256').count(),
        }

        agg = files.aggregate(
            avg_enc=Avg('encryption_time'),
            avg_dec=Avg('decryption_time'),
        )

        sensitivity_dist = {
            label: files.filter(sensitivity_level=level).count()
            for level, label in EncryptedFile.SENSITIVITY_CHOICES
        }

        return JsonResponse({
            'encryption_distribution': enc_dist,
            'sensitivity_distribution': sensitivity_dist,
            'avg_encryption_time': round(agg['avg_enc'] or 0, 2),
            'avg_decryption_time': round(agg['avg_dec'] or 0, 2),
            'total_files': files.count(),
            'total_size_mb': round(
                (files.aggregate(s=Avg('original_size'))['s'] or 0) / (1024 * 1024), 2
            ),
        })


# URL-compatible aliases
upload_file_view = UploadFileView.as_view()
download_file_view = DownloadEncryptedView.as_view()
decrypt_file_view = DecryptFileView.as_view()
verify_integrity_view = VerifyIntegrityView.as_view()
encryption_stats_api = EncryptionStatsAPIView.as_view()

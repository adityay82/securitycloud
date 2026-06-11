"""
File Manager views — upgraded to CBVs.
Supports admin view (all files) and user view (own files).
"""
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.views import View
from django.db.models import Sum

from encryption.models import EncryptedFile
from audit.models import AuditLog
from authentication.utils import get_client_ip


class FileListView(LoginRequiredMixin, View):
    """List files — admin sees all, users see their own."""

    def get(self, request):
        if request.user.role == 'admin':
            files = EncryptedFile.objects.filter(
                is_deleted=False
            ).select_related('user').order_by('-uploaded_at')
        else:
            files = EncryptedFile.objects.filter(
                user=request.user, is_deleted=False
            ).order_by('-uploaded_at')

        # Stats
        total = files.count()
        encrypted = files.filter(status='encrypted').count()
        aes128 = files.filter(encryption_type='AES-128').count()
        aes192 = files.filter(encryption_type='AES-192').count()
        aes256 = files.filter(encryption_type='AES-256').count()
        total_size = files.aggregate(s=Sum('original_size'))['s'] or 0

        return render(request, 'filemanager/list.html', {
            'files': files,
            'total': total,
            'encrypted': encrypted,
            'aes128': aes128,
            'aes192': aes192,
            'aes256': aes256,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'is_admin': request.user.role == 'admin',
            'page_title': 'Secure File Manager',
        })


class DeleteFileView(LoginRequiredMixin, View):
    """Soft-delete an encrypted file."""

    def post(self, request, file_id):
        if request.user.role == 'admin':
            f = get_object_or_404(EncryptedFile, id=file_id, is_deleted=False)
        else:
            f = get_object_or_404(
                EncryptedFile, id=file_id, user=request.user, is_deleted=False
            )
        f.is_deleted = True
        f.save(update_fields=['is_deleted'])
        AuditLog.objects.create(
            user=request.user, action='file_deleted',
            description=f'File deleted: {f.original_filename}',
            ip_address=get_client_ip(request), severity='medium',
        )
        messages.success(request, f'File "{f.original_filename}" deleted.')
        return redirect('filemanager:list')

    def get(self, request, file_id):
        """Fallback GET — just redirect (DELETE should be POST)."""
        return redirect('filemanager:list')


# URL aliases
file_list_view = FileListView.as_view()
delete_file_view = DeleteFileView.as_view()

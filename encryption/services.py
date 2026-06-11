"""
Encryption Service Layer for CloudSec.

Handles all file encryption, decryption, integrity verification,
and optionally cloud storage abstraction.
"""
import os
import logging
from django.conf import settings
from django.core.files.base import ContentFile
from django.utils import timezone

from .crypto import (
    encrypt_file, decrypt_file, verify_integrity,
    select_encryption_type, compute_file_hash,
)
from .models import EncryptedFile
from audit.models import AuditLog

logger = logging.getLogger(__name__)

# Allowed file types: (MIME type, magic bytes, extension)
ALLOWED_FILE_TYPES = {
    'application/pdf': (b'%PDF', ['.pdf']),
    'image/jpeg': (b'\xff\xd8\xff', ['.jpg', '.jpeg']),
    'image/png': (b'\x89PNG', ['.png']),
    'image/gif': (b'GIF8', ['.gif']),
    'image/webp': (None, ['.webp']),
    'text/plain': (None, ['.txt', '.log', '.csv', '.md']),
    'application/json': (None, ['.json']),
    'application/zip': (b'PK\x03\x04', ['.zip']),
    'application/msword': (b'\xd0\xcf\x11\xe0', ['.doc']),
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': (
        b'PK\x03\x04', ['.docx']
    ),
    'application/vnd.ms-excel': (b'\xd0\xcf\x11\xe0', ['.xls']),
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': (
        b'PK\x03\x04', ['.xlsx']
    ),
}

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB


class FileValidationError(Exception):
    """Raised when uploaded file fails security validation."""
    pass


class EncryptionService:
    """Central service for file encryption and decryption operations."""

    @staticmethod
    def validate_upload(uploaded_file) -> None:
        """
        Validate file type, size, and magic bytes.
        Raises FileValidationError on any violation.
        """
        # Size check
        if uploaded_file.size > MAX_FILE_SIZE_BYTES:
            raise FileValidationError(
                f"File too large. Maximum size is {MAX_FILE_SIZE_BYTES // (1024*1024)}MB. "
                f"Your file: {uploaded_file.size // (1024*1024)}MB."
            )

        # Extension check
        original_name = uploaded_file.name.lower()
        ext = os.path.splitext(original_name)[1]
        allowed_extensions = []
        for mime_type, (magic, exts) in ALLOWED_FILE_TYPES.items():
            allowed_extensions.extend(exts)

        if ext not in allowed_extensions:
            raise FileValidationError(
                f"File type '{ext}' is not allowed. "
                f"Permitted types: {', '.join(set(allowed_extensions))}"
            )

        # Magic bytes check (first 8 bytes)
        uploaded_file.seek(0)
        header = uploaded_file.read(8)
        uploaded_file.seek(0)

        # Find matching magic bytes
        for mime_type, (magic, exts) in ALLOWED_FILE_TYPES.items():
            if ext in exts and magic is not None:
                if not header.startswith(magic):
                    raise FileValidationError(
                        f"File content does not match extension '{ext}'. "
                        "Possible file spoofing attempt detected."
                    )
                break

    @staticmethod
    def encrypt_and_store(
        uploaded_file, user, risk_score: float = 0.0, sensitivity: str = 'medium'
    ) -> EncryptedFile:
        """
        Read, validate, encrypt, and store an uploaded file.
        
        Adaptive encryption selection:
          - risk_score >= 0.7 → always AES-256 (regardless of size)
          - sensitivity == 'critical' → always AES-256
          - otherwise → size-based selection
        
        Returns the created EncryptedFile instance.
        """
        EncryptionService.validate_upload(uploaded_file)

        uploaded_file.seek(0)
        file_data = uploaded_file.read()
        file_size = len(file_data)

        # Adaptive encryption type
        if risk_score >= 0.7 or sensitivity == 'critical':
            encryption_type = 'AES-256'
            logger.info(
                f"Forcing AES-256 for user {user.username} "
                f"(risk={risk_score:.2f}, sensitivity={sensitivity})"
            )
        else:
            encryption_type = select_encryption_type(file_size)

        result = encrypt_file(file_data, encryption_type)

        # Save encrypted file
        enc_content = ContentFile(result['encrypted_data'])
        enc_filename = f"enc_{uploaded_file.name}"

        enc_file = EncryptedFile.objects.create(
            user=user,
            original_filename=uploaded_file.name,
            original_size=file_size,
            encryption_type=result['encryption_type'],
            encryption_key=result['key_hex'],
            encryption_iv=result['iv_hex'],
            status='encrypted',
            file_hash=result['original_hash'],
            encryption_time=result['encryption_time_ms'],
            encrypted_at=timezone.now(),
            sensitivity_level=sensitivity,
            risk_score_at_upload=risk_score,
        )
        enc_file.file_path.save(enc_filename, enc_content)

        logger.info(
            f"File '{uploaded_file.name}' encrypted with {encryption_type} "
            f"in {result['encryption_time_ms']:.2f}ms for user {user.username}"
        )
        return enc_file

    @staticmethod
    def decrypt_for_download(enc_file: EncryptedFile) -> dict:
        """
        Decrypt an EncryptedFile and verify integrity.
        Returns dict with decrypted_data, integrity_ok, decryption_time_ms.
        Raises FileNotFoundError or ValueError on failure.
        """
        file_path = enc_file.file_path.path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Encrypted file not found on disk: {file_path}")

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        result = decrypt_file(encrypted_data, enc_file.encryption_key, enc_file.encryption_iv)
        decrypted_data = result['decrypted_data']
        integrity_ok = verify_integrity(decrypted_data, enc_file.file_hash)

        # Update stats
        enc_file.decryption_time = result['decryption_time_ms']
        enc_file.access_count = (enc_file.access_count or 0) + 1
        enc_file.last_accessed = timezone.now()
        enc_file.save(update_fields=['decryption_time', 'access_count', 'last_accessed'])

        return {
            'decrypted_data': decrypted_data,
            'integrity_ok': integrity_ok,
            'decryption_time_ms': result['decryption_time_ms'],
        }

    @staticmethod
    def verify_file_integrity(enc_file: EncryptedFile) -> dict:
        """
        Verify file integrity without returning data to the user.
        Returns status dict for AJAX response.
        """
        try:
            result = EncryptionService.decrypt_for_download(enc_file)
            return {
                'status': 'ok' if result['integrity_ok'] else 'failed',
                'integrity': result['integrity_ok'],
                'filename': enc_file.original_filename,
                'hash': enc_file.file_hash,
                'decryption_time_ms': result['decryption_time_ms'],
                'message': (
                    '✅ File integrity verified — no tampering detected.'
                    if result['integrity_ok']
                    else '⚠️ INTEGRITY FAILED — File may have been tampered with!'
                ),
            }
        except FileNotFoundError:
            return {'status': 'error', 'message': 'File not found on server.'}
        except Exception as e:
            logger.error(f"Integrity check error for {enc_file.id}: {e}")
            return {'status': 'error', 'message': f'Verification failed: {str(e)}'}

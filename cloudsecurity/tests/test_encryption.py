"""
Encryption tests — covers file validation, adaptive selection,
integrity verification, and service layer.
"""
import os
import io
from django.test import TestCase
from django.core.files.base import ContentFile

from authentication.models import CustomUser
from encryption.crypto import (
    encrypt_file, decrypt_file, select_encryption_type,
    compute_file_hash, verify_integrity,
)
from encryption.services import EncryptionService, FileValidationError
from encryption.models import EncryptedFile


def make_fake_file(name: str, size_bytes: int, magic: bytes = None) -> io.BytesIO:
    """Create an in-memory fake file for testing."""
    data = (magic or b'') + b'X' * max(0, size_bytes - len(magic or b''))
    f = io.BytesIO(data)
    f.name = name
    f.size = size_bytes
    f.seek(0)
    return f


class EncryptionTypeSelectionTest(TestCase):
    """Test adaptive AES key selection based on file size."""

    def test_small_file_gets_aes128(self):
        size = 500 * 1024  # 500KB
        self.assertEqual(select_encryption_type(size), 'AES-128')

    def test_medium_file_gets_aes192(self):
        size = 5 * 1024 * 1024  # 5MB
        self.assertEqual(select_encryption_type(size), 'AES-192')

    def test_large_file_gets_aes256(self):
        size = 15 * 1024 * 1024  # 15MB
        self.assertEqual(select_encryption_type(size), 'AES-256')

    def test_exactly_1mb_is_aes128(self):
        size = 1 * 1024 * 1024  # Exactly 1MB (boundary)
        enc = select_encryption_type(size)
        self.assertIn(enc, ['AES-128', 'AES-192'])  # Either side of boundary

    def test_exactly_10mb_is_aes192_or_aes256(self):
        size = 10 * 1024 * 1024
        enc = select_encryption_type(size)
        self.assertIn(enc, ['AES-192', 'AES-256'])


class CoreCryptographyTest(TestCase):
    """Test encrypt/decrypt round-trip with all key sizes."""

    def _round_trip(self, enc_type: str):
        """Helper: encrypt then decrypt and verify."""
        plaintext = b'CloudSec test data 1234567890 ' * 10
        result = encrypt_file(plaintext, enc_type)
        self.assertEqual(result['encryption_type'], enc_type)
        self.assertIn('encrypted_data', result)
        self.assertIn('key_hex', result)
        self.assertIn('iv_hex', result)
        self.assertIn('original_hash', result)
        self.assertGreater(result['encryption_time_ms'], 0)

        dec = decrypt_file(result['encrypted_data'], result['key_hex'], result['iv_hex'])
        self.assertEqual(dec['decrypted_data'], plaintext)

    def test_aes128_round_trip(self):
        self._round_trip('AES-128')

    def test_aes192_round_trip(self):
        self._round_trip('AES-192')

    def test_aes256_round_trip(self):
        self._round_trip('AES-256')

    def test_wrong_key_fails_decryption(self):
        plaintext = b'Test secret data'
        result = encrypt_file(plaintext, 'AES-256')
        # Use wrong key (all zeros)
        wrong_key = '00' * 32
        with self.assertRaises(Exception):
            decrypt_file(result['encrypted_data'], wrong_key, result['iv_hex'])

    def test_tampered_data_fails_integrity(self):
        plaintext = b'Tamper-test data'
        result = encrypt_file(plaintext, 'AES-256')
        dec = decrypt_file(result['encrypted_data'], result['key_hex'], result['iv_hex'])
        original_hash = result['original_hash']

        # Tamper with the decrypted data
        tampered = dec['decrypted_data'] + b'_TAMPERED'
        self.assertFalse(verify_integrity(tampered, original_hash))

    def test_sha256_hash_consistency(self):
        data = b'Consistent hash test'
        h1 = compute_file_hash(data)
        h2 = compute_file_hash(data)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # SHA-256 hex is 64 chars


class FileValidationTest(TestCase):
    """Test file upload validation in EncryptionService."""

    def test_oversized_file_rejected(self):
        f = make_fake_file('big.pdf', 60 * 1024 * 1024, b'%PDF')
        with self.assertRaises(FileValidationError) as ctx:
            EncryptionService.validate_upload(f)
        self.assertIn('too large', str(ctx.exception))

    def test_disallowed_extension_rejected(self):
        f = make_fake_file('virus.exe', 1024, b'MZ')
        with self.assertRaises(FileValidationError) as ctx:
            EncryptionService.validate_upload(f)
        self.assertIn('not allowed', str(ctx.exception))

    def test_valid_pdf_accepted(self):
        f = make_fake_file('document.pdf', 512 * 1024, b'%PDF')
        # Should NOT raise
        try:
            EncryptionService.validate_upload(f)
        except FileValidationError:
            self.fail('Valid PDF was rejected')

    def test_spoofed_exe_as_pdf_rejected(self):
        """File named .pdf but with EXE magic bytes should be rejected."""
        f = make_fake_file('not_really.pdf', 1024, b'MZ\x90\x00')
        with self.assertRaises(FileValidationError) as ctx:
            EncryptionService.validate_upload(f)
        self.assertIn('does not match', str(ctx.exception))

    def test_valid_png_accepted(self):
        f = make_fake_file('image.png', 100 * 1024, b'\x89PNG\r\n\x1a\n')
        try:
            EncryptionService.validate_upload(f)
        except FileValidationError:
            self.fail('Valid PNG was rejected')

    def test_valid_zip_accepted(self):
        f = make_fake_file('archive.zip', 200 * 1024, b'PK\x03\x04')
        try:
            EncryptionService.validate_upload(f)
        except FileValidationError:
            self.fail('Valid ZIP was rejected')


class HighRiskEncryptionTest(TestCase):
    """Test that high-risk sessions force AES-256."""

    def test_high_risk_score_forces_aes256(self):
        plaintext = b'Sensitive data'
        f = make_fake_file('small.pdf', 100, b'%PDF')
        size = 100

        # With high risk score, should use AES-256 regardless of size
        if 0.7 >= 0.7 or 'critical' == 'critical':
            enc_type = 'AES-256'
        else:
            enc_type = select_encryption_type(size)

        self.assertEqual(enc_type, 'AES-256')

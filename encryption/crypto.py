"""
Adaptive AES Encryption/Decryption Module.
Automatically selects AES-128, AES-192, or AES-256 based on file size.
Includes key wrapping for defense-in-depth key storage.
"""

import os
import time
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging

logger = logging.getLogger(__name__)

# Thresholds
AES_128_THRESHOLD = 1 * 1024 * 1024    # 1 MB
AES_192_THRESHOLD = 10 * 1024 * 1024   # 10 MB

# Key sizes in bytes
KEY_SIZES = {
    'AES-128': 16,  # 128 bits
    'AES-192': 24,  # 192 bits
    'AES-256': 32,  # 256 bits
}

# Master key for wrapping file encryption keys (from environment)
# In production: use AWS KMS, HashiCorp Vault, or Azure Key Vault
_MASTER_KEY_STR = os.environ.get('MASTER_KEY', 'cloudsec-default-master-key-32b!')
MASTER_KEY = _MASTER_KEY_STR.encode('utf-8')[:32].ljust(32, b'\0')


def wrap_key(key_hex: str) -> str:
    """
    Encrypt a file encryption key with the master key using AES-GCM.
    Returns a hex string containing nonce + tag + ciphertext.
    This ensures keys are never stored in plaintext in the database.
    """
    cipher = AES.new(MASTER_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(bytes.fromhex(key_hex))
    # Pack as: nonce(16) + tag(16) + ciphertext(variable)
    wrapped = cipher.nonce + tag + ciphertext
    return wrapped.hex()


def unwrap_key(wrapped_hex: str) -> str:
    """
    Decrypt a wrapped file encryption key using the master key.
    Raises ValueError if the key has been tampered with.
    """
    data = bytes.fromhex(wrapped_hex)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(MASTER_KEY, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.hex()


def select_encryption_type(file_size_bytes: int) -> str:
    """Adaptive encryption selection based on file size."""
    if file_size_bytes < AES_128_THRESHOLD:
        return 'AES-128'
    elif file_size_bytes < AES_192_THRESHOLD:
        return 'AES-192'
    else:
        return 'AES-256'


def generate_key(encryption_type: str) -> bytes:
    """Generate a cryptographically secure key."""
    key_size = KEY_SIZES[encryption_type]
    return secrets.token_bytes(key_size)


def generate_iv() -> bytes:
    """Generate a random 16-byte IV for AES-CBC."""
    return secrets.token_bytes(16)


def compute_file_hash(file_data: bytes) -> str:
    """Compute SHA-256 hash for integrity verification."""
    return hashlib.sha256(file_data).hexdigest()


def encrypt_file(file_data: bytes, encryption_type: str = None) -> dict:
    """
    Encrypt file data using AES-CBC with adaptive key selection.
    The returned key_hex is wrapped (encrypted) with the master key.
    
    Returns:
        dict with encrypted_data, key_hex (wrapped), iv_hex, encryption_type,
        encryption_time_ms, original_hash
    """
    file_size = len(file_data)
    if not encryption_type:
        encryption_type = select_encryption_type(file_size)

    key = generate_key(encryption_type)
    iv = generate_iv()
    original_hash = compute_file_hash(file_data)

    start_time = time.perf_counter()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    end_time = time.perf_counter()
    encryption_time_ms = (end_time - start_time) * 1000

    # Wrap the key before returning (never store plaintext keys)
    wrapped_key = wrap_key(key.hex())

    logger.info(f"Encrypted {file_size} bytes using {encryption_type} in {encryption_time_ms:.2f}ms")

    return {
        'encrypted_data': encrypted_data,
        'key_hex': wrapped_key,
        'iv_hex': iv.hex(),
        'encryption_type': encryption_type,
        'encryption_time_ms': round(encryption_time_ms, 2),
        'original_hash': original_hash,
    }


def decrypt_file(encrypted_data: bytes, key_hex: str, iv_hex: str) -> dict:
    """
    Decrypt AES-encrypted data.
    key_hex should be a wrapped key — it will be unwrapped automatically.
    Falls back to treating it as a plaintext key for backward compatibility.
    
    Returns:
        dict with decrypted_data, decryption_time_ms
    """
    # Try unwrapping first; fall back to plaintext for old files
    try:
        actual_key_hex = unwrap_key(key_hex)
    except (ValueError, Exception):
        # Backward compatibility: key was stored in plaintext
        actual_key_hex = key_hex
        logger.warning("Using unwrapped (plaintext) key — consider re-encrypting this file.")

    key = bytes.fromhex(actual_key_hex)
    iv = bytes.fromhex(iv_hex)

    start_time = time.perf_counter()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_data)
    decrypted_data = unpad(decrypted_padded, AES.block_size)

    end_time = time.perf_counter()
    decryption_time_ms = (end_time - start_time) * 1000

    logger.info(f"Decrypted {len(encrypted_data)} bytes in {decryption_time_ms:.2f}ms")

    return {
        'decrypted_data': decrypted_data,
        'decryption_time_ms': round(decryption_time_ms, 2),
    }


def verify_integrity(decrypted_data: bytes, original_hash: str) -> bool:
    """Verify file integrity using SHA-256 hash comparison."""
    current_hash = compute_file_hash(decrypted_data)
    return current_hash == original_hash


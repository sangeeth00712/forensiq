
import hashlib
import logging
import re
import unicodedata
from pathlib import Path
from typing import Tuple

import config
from core.logger import get_logger

logger = get_logger(__name__)


# PCAP magic bytes (file signatures)
# These are the actual bytes that start a valid PCAP file
PCAP_MAGIC_BYTES = {
    b"\xd4\xc3\xb2\xa1",  # PCAP little-endian
    b"\xa1\xb2\xc3\xd4",  # PCAP big-endian
    b"\x0a\x0d\x0d\x0a",  # PCAPng
}


class ValidationError(Exception):
    """
    Raised when a file fails validation.
    Contains user-safe message (no internal details exposed).
    """
    pass


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes filename to prevent path traversal attacks.

    Prevents attacks like:
        "../../../../etc/passwd"  → rejected
        "file<script>.pcap"       → rejected
        "valid_capture.pcap"      → accepted

    Args:
        filename: Raw filename from user upload

    Returns:
        Sanitized filename safe for file system

    Raises:
        ValidationError: If filename cannot be made safe
    """
    if not filename:
        raise ValidationError("Filename cannot be empty.")

    # Normalize unicode — prevents unicode bypass attacks
    filename = unicodedata.normalize("NFKC", filename)

    # Extract just the filename — strip any directory components
    # This is the core path traversal prevention
    filename = Path(filename).name

    # Remove any character that isn't alphanumeric, dash,
    # underscore, or dot — strict allowlist
    filename = re.sub(r"[^\w\-.]", "_", filename)

    # Prevent hidden files (dot-files)
    if filename.startswith("."):
        raise ValidationError("Hidden files are not accepted.")

    # Enforce maximum length
    if len(filename) > config.MAX_FILENAME_LENGTH:
        raise ValidationError(
            f"Filename too long. Maximum {config.MAX_FILENAME_LENGTH} characters."
        )

    if not filename:
        raise ValidationError("Filename became empty after sanitization.")

    logger.debug(f"Filename sanitized: {filename}")
    return filename


def validate_extension(filename: str) -> None:
    """
    Validates file extension against allowlist.

    Security note: Extension check alone is NOT sufficient
    (attacker can rename any file to .pcap).
    This is one of multiple validation layers.

    Args:
        filename: Sanitized filename

    Raises:
        ValidationError: If extension not in allowlist
    """
    suffix = Path(filename).suffix.lower()

    if suffix not in config.ALLOWED_EXTENSIONS:
        raise ValidationError(
            f"File type '{suffix}' is not supported. "
            f"Accepted types: {', '.join(config.ALLOWED_EXTENSIONS)}"
        )

    logger.debug(f"Extension valid: {suffix}")


def validate_file_size(file_path: Path) -> None:
    """
    Validates file does not exceed maximum allowed size.

    Security note: Prevents resource exhaustion attacks
    where attacker uploads enormous files to crash the system.

    Args:
        file_path: Path to uploaded file on disk

    Raises:
        ValidationError: If file exceeds size limit
    """
    size = file_path.stat().st_size

    if size == 0:
        raise ValidationError("Uploaded file is empty.")

    if size > config.MAX_FILE_SIZE_BYTES:
        max_mb = config.MAX_FILE_SIZE_BYTES // (1024 * 1024)
        actual_mb = size // (1024 * 1024)
        raise ValidationError(
            f"File too large: {actual_mb}MB. "
            f"Maximum allowed: {max_mb}MB. "
            f"Please split the capture and try again."
        )

    logger.debug(f"File size valid: {size} bytes")


def validate_magic_bytes(file_path: Path) -> None:
    """
    Validates file starts with known PCAP magic bytes.

    This is the MOST IMPORTANT validation — it checks actual
    file content, not just the filename.

    An attacker who renames 'malware.exe' to 'capture.pcap'
    will fail this check because the magic bytes won't match.

    Args:
        file_path: Path to uploaded file on disk

    Raises:
        ValidationError: If file is not a valid PCAP
    """
    try:
        with open(file_path, "rb") as f:
            # Read only first 4 bytes — safe, minimal I/O
            header = f.read(4)
    except OSError as e:
        # Log internal error but don't expose details to user
        logger.error(f"Failed to read file header: {e}")
        raise ValidationError(
            "Could not read file. Please try again."
        )

    if header not in PCAP_MAGIC_BYTES:
        raise ValidationError(
            "File does not appear to be a valid PCAP file. "
            "Please upload a file captured with Wireshark, "
            "tcpdump, or similar tools."
        )

    logger.debug("Magic bytes valid — file is PCAP")


def compute_sha256(file_path: Path) -> str:
    """
    Computes SHA-256 hash of uploaded file.

    Used for:
    1. Deduplication — don't re-analyze same file twice
    2. Chain of custody — hash goes into forensics report
    3. Integrity verification — detect file corruption

    Args:
        file_path: Path to file on disk

    Returns:
        Lowercase hex string SHA-256 hash
    """
    sha256 = hashlib.sha256()

    # Read in chunks — safe for large files
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)

    hash_value = sha256.hexdigest()
    logger.debug(f"SHA256 computed: {hash_value}")
    return hash_value


def validate_pcap_file(file_path: Path) -> Tuple[str, str]:
    """
    Master validation function — runs ALL checks in order.

    This is the ONLY function the rest of ForensiQ should call
    to validate an uploaded file. Never bypass this.

    Validation order matters:
    1. Sanitize filename (cheapest check first)
    2. Check extension (fast string check)
    3. Check file size (single stat() call)
    4. Check magic bytes (minimal file read)
    5. Compute hash (full file read — most expensive, done last)

    Args:
        file_path: Path to the uploaded file

    Returns:
        Tuple of (sanitized_filename, sha256_hash)

    Raises:
        ValidationError: If any check fails
    """
    logger.info(f"Starting validation: {file_path.name}")

    try:
        # Step 1: Sanitize filename
        safe_name = sanitize_filename(file_path.name)

        # Step 2: Check extension
        validate_extension(safe_name)

        # Step 3: Check file size
        validate_file_size(file_path)

        # Step 4: Check magic bytes (content validation)
        validate_magic_bytes(file_path)

        # Step 5: Compute SHA-256 for chain of custody
        file_hash = compute_sha256(file_path)

        logger.info(
            f"File validation PASSED | "
            f"Name: {safe_name} | SHA256: {file_hash}"
        )

        return safe_name, file_hash

    except ValidationError as e:
        logger.warning(f"File validation FAILED: {e}")
        raise

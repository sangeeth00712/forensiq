import pytest
import tempfile
from pathlib import Path

from core.validator import (
    sanitize_filename,
    validate_extension,
    validate_file_size,
    validate_magic_bytes,
    compute_sha256,
    validate_pcap_file,
    ValidationError,
)


class TestSanitizeFilename:

    def test_valid_filename_passes(self):
        assert sanitize_filename("capture.pcap") == "capture.pcap"

    def test_path_traversal_blocked(self):
        result = sanitize_filename("../../../../etc/passwd.pcap")
        assert "/" not in result
        assert ".." not in result
        assert result == "passwd.pcap"

    def test_windows_path_traversal_blocked(self):
        result = sanitize_filename("file.pcap")
        assert result == "file.pcap"

    def test_empty_filename_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_filename("")

    def test_hidden_file_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_filename(".hidden.pcap")

    def test_special_characters_removed(self):
        result = sanitize_filename("file<>|*.pcap")
        assert "<" not in result
        assert ">" not in result

    def test_spaces_converted(self):
        result = sanitize_filename("my capture.pcap")
        assert " " not in result


class TestValidateExtension:

    def test_pcap_accepted(self):
        validate_extension("capture.pcap")

    def test_pcapng_accepted(self):
        validate_extension("capture.pcapng")

    def test_cap_accepted(self):
        validate_extension("capture.cap")

    def test_exe_rejected(self):
        with pytest.raises(ValidationError):
            validate_extension("malware.exe")

    def test_zip_rejected(self):
        with pytest.raises(ValidationError):
            validate_extension("bomb.zip")

    def test_case_insensitive(self):
        validate_extension("CAPTURE.PCAP")


class TestValidateFileSize:

    def test_empty_file_rejected(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)
        try:
            with pytest.raises(ValidationError):
                validate_file_size(temp_path)
        finally:
            temp_path.unlink()

    def test_valid_size_accepted(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00" * 1024)
            temp_path = Path(f.name)
        try:
            validate_file_size(temp_path)
        finally:
            temp_path.unlink()


class TestValidateMagicBytes:

    def test_valid_pcap_magic_accepted(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
            temp_path = Path(f.name)
        try:
            validate_magic_bytes(temp_path)
        finally:
            temp_path.unlink()

    def test_exe_rejected(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 100)
            temp_path = Path(f.name)
        try:
            with pytest.raises(ValidationError):
                validate_magic_bytes(temp_path)
        finally:
            temp_path.unlink()


class TestComputeSHA256:

    def test_hash_is_64_characters(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            temp_path = Path(f.name)
        try:
            result = compute_sha256(temp_path)
            assert len(result) == 64
        finally:
            temp_path.unlink()

    def test_same_file_same_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"consistent data")
            temp_path = Path(f.name)
        try:
            assert compute_sha256(temp_path) == compute_sha256(temp_path)
        finally:
            temp_path.unlink()


class TestValidatePcapFile:

    def test_valid_pcap_passes(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 1000)
            temp_path = Path(f.name)
        try:
            safe_name, file_hash = validate_pcap_file(temp_path)
            assert safe_name.endswith(".pcap")
            assert len(file_hash) == 64
        finally:
            temp_path.unlink()

    def test_invalid_extension_fails(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 1000)
            temp_path = Path(f.name)
        try:
            with pytest.raises(ValidationError):
                validate_pcap_file(temp_path)
        finally:
            temp_path.unlink()

    def test_invalid_magic_fails(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"NOT_PCAP" + b"\x00" * 1000)
            temp_path = Path(f.name)
        try:
            with pytest.raises(ValidationError):
                validate_pcap_file(temp_path)
        finally:
            temp_path.unlink()

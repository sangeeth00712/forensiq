# tests/test_models.py
# ─────────────────────────────────────────────
# ForensiQ — Unit Tests for Core Models
#
# Run with: pytest tests/test_models.py -v
#
# These tests ensure data models are:
#   - Created correctly
#   - Cannot be created in invalid states
#   - Serialize to JSON correctly
# ─────────────────────────────────────────────

import pytest
import json
from datetime import datetime

from core.models import (
    Flow, IOC, Finding, AnalysisReport,
    Severity, Protocol, IOCType, RuleCategory
)


# ──────────────────────────────────
# FIXTURES — Reusable test objects
# ──────────────────────────────────

@pytest.fixture
def sample_flow() -> Flow:
    """A valid flow for testing."""
    return Flow(
        src_ip            = "192.168.1.10",
        dst_ip            = "10.0.0.1",
        src_port          = 52341,
        dst_port          = 80,
        protocol          = Protocol.TCP,
        first_seen        = datetime(2026, 5, 1, 10, 0, 0),
        last_seen         = datetime(2026, 5, 1, 10, 0, 5),
        packet_count      = 10,
        bytes_transferred = 1500,
    )


@pytest.fixture
def sample_ioc() -> IOC:
    """A valid IOC for testing."""
    return IOC(
        value    = "192.168.1.10",
        ioc_type = IOCType.IP,
    )


@pytest.fixture
def sample_finding() -> Finding:
    """A valid finding for testing."""
    return Finding(
        rule_name        = "PORT_SCAN_DETECTED",
        severity         = Severity.HIGH,
        category         = RuleCategory.RECONNAISSANCE,
        title            = "Port Scan Detected",
        description      = "Host scanned 15 unique ports.",
        evidence         = {
            "scanned_ports": [22, 80, 443, 3306, 8080],
            "total_ports": 15,
            "duration": 45,
        },
        src_ip           = "192.168.1.10",
        dst_ip           = "10.0.0.1",
        timestamp        = datetime(2026, 5, 1, 10, 0, 0),
        mitre_technique  = "T1046",
        mitre_tactic     = "Discovery",
    )


# ──────────────────────────────────
# FLOW TESTS
# ──────────────────────────────────

class TestFlow:
    """Tests for Flow data model."""

    def test_flow_created_successfully(self, sample_flow: Flow) -> None:
        """Flow must be created without errors."""
        assert sample_flow.src_ip == "192.168.1.10"
        assert sample_flow.dst_port == 80

    def test_duration_calculated(self, sample_flow: Flow) -> None:
        """Duration should be 5 seconds for our fixture."""
        assert sample_flow.duration_seconds == 5.0

    def test_duration_zero_for_single_packet(self) -> None:
        """Single-packet flow should have 0 duration."""
        now = datetime(2026, 5, 1, 10, 0, 0)
        flow = Flow(
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1234, dst_port=80,
            protocol=Protocol.TCP,
            first_seen=now, last_seen=now,
        )
        assert flow.duration_seconds == 0.0

    def test_bytes_per_second(self, sample_flow: Flow) -> None:
        """Bytes per second = bytes / duration."""
        # 1500 bytes / 5 seconds = 300 bytes/sec
        assert sample_flow.bytes_per_second == 300.0

    def test_bytes_per_second_zero_duration(self) -> None:
        """Should return 0 if duration is 0."""
        now = datetime.now()
        flow = Flow(
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1234, dst_port=80,
            protocol=Protocol.TCP,
            first_seen=now, last_seen=now,
            bytes_transferred=1000,
        )
        assert flow.bytes_per_second == 0.0

    def test_flow_id_format(self, sample_flow: Flow) -> None:
        """Flow ID must be correctly formatted."""
        expected = "192.168.1.10:52341-10.0.0.1:80-TCP"
        assert sample_flow.flow_id == expected

    def test_flow_to_dict_json_safe(self, sample_flow: Flow) -> None:
        """to_dict() output must be JSON-serializable."""
        d = sample_flow.to_dict()
        # Should not raise
        json.dumps(d)

    def test_flow_to_dict_has_required_keys(self, sample_flow: Flow) -> None:
        """Dict must contain all required keys."""
        d = sample_flow.to_dict()
        required = ["flow_id", "src_ip", "dst_ip", "protocol", 
                    "first_seen", "last_seen", "duration_seconds"]
        for key in required:
            assert key in d


# ──────────────────────────────────
# IOC TESTS
# ──────────────────────────────────

class TestIOC:
    """Tests for IOC data model."""

    def test_ioc_created_successfully(self, sample_ioc: IOC) -> None:
        """IOC must be created without errors."""
        assert sample_ioc.value == "192.168.1.10"
        assert sample_ioc.ioc_type == IOCType.IP

    def test_ioc_unenriched_by_default(self) -> None:
        """New IOC should start unenriched."""
        ioc = IOC(value="example.com", ioc_type=IOCType.DOMAIN)
        assert ioc.enriched is False
        assert ioc.malicious is False
        assert ioc.vt_score is None

    def test_ioc_to_dict_json_safe(self, sample_ioc: IOC) -> None:
        """to_dict() output must be JSON-serializable."""
        d = sample_ioc.to_dict()
        json.dumps(d)

    def test_ioc_string_representation(self, sample_ioc: IOC) -> None:
        """__str__ should return human-readable format."""
        s = str(sample_ioc)
        assert "192.168.1.10" in s
        assert "ip" in s


# ──────────────────────────────────
# FINDING TESTS
# ──────────────────────────────────

class TestFinding:
    """Tests for Finding data model."""

    def test_finding_created_successfully(self, sample_finding: Finding) -> None:
        """Valid finding must be created."""
        assert sample_finding.rule_name == "PORT_SCAN_DETECTED"
        assert sample_finding.severity == Severity.HIGH

    def test_finding_rejects_empty_evidence(self) -> None:
        """CRITICAL: Finding with empty evidence must raise ValueError."""
        with pytest.raises(ValueError, match="empty evidence"):
            Finding(
                rule_name       = "TEST_RULE",
                severity        = Severity.LOW,
                category        = RuleCategory.RECONNAISSANCE,
                title           = "Test",
                description     = "Test",
                evidence        = {},
                src_ip          = "1.1.1.1",
                dst_ip          = "2.2.2.2",
                timestamp       = datetime.now(),
                mitre_technique = "T1046",
                mitre_tactic    = "Discovery",
            )

    def test_finding_rejects_invalid_confidence(self) -> None:
        """Confidence outside 0.0-1.0 must raise ValueError."""
        with pytest.raises(ValueError, match="Confidence"):
            Finding(
                rule_name       = "TEST_RULE",
                severity        = Severity.LOW,
                category        = RuleCategory.RECONNAISSANCE,
                title           = "Test",
                description     = "Test",
                evidence        = {"key": "value"},
                src_ip          = "1.1.1.1",
                dst_ip          = "2.2.2.2",
                timestamp       = datetime.now(),
                mitre_technique = "T1046",
                mitre_tactic    = "Discovery",
                confidence      = 1.5,
            )

    def test_finding_to_dict_json_safe(self, sample_finding: Finding) -> None:
        """to_dict() output must be JSON-serializable."""
        d = sample_finding.to_dict()
        json.dumps(d)

    def test_finding_to_json_string(self, sample_finding: Finding) -> None:
        """to_json() should return valid JSON string."""
        json_str = sample_finding.to_json()
        parsed = json.loads(json_str)
        assert parsed["rule_name"] == "PORT_SCAN_DETECTED"


# ──────────────────────────────────
# ANALYSIS REPORT TESTS
# ──────────────────────────────────

class TestAnalysisReport:
    """Tests for AnalysisReport data model."""

    def test_report_created_successfully(self) -> None:
        """Report must be created without errors."""
        now = datetime.now()
        report = AnalysisReport(
            pcap_filename="test.pcap",
            pcap_hash="abc123",
            analysis_start=now,
            analysis_end=now,
        )
        assert report.pcap_filename == "test.pcap"

    def test_report_duration_calculated(self) -> None:
        """Duration must be calculated from start/end times."""
        start = datetime(2026, 5, 1, 10, 0, 0)
        end   = datetime(2026, 5, 1, 10, 0, 10)
        report = AnalysisReport(
            pcap_filename="test.pcap",
            pcap_hash="abc123",
            analysis_start=start,
            analysis_end=end,
        )
        assert report.duration_seconds == 10.0

    def test_report_finding_count_by_severity(self, sample_finding: Finding) -> None:
        """Report should count findings by severity."""
        now = datetime.now()
        report = AnalysisReport(
            pcap_filename="test.pcap",
            pcap_hash="abc123",
            analysis_start=now,
            analysis_end=now,
            findings=[sample_finding],
        )
        counts = report.finding_count_by_severity
        assert counts["HIGH"] == 1
        assert counts["CRITICAL"] == 0

    def test_report_has_critical_findings(self) -> None:
        """has_critical_findings should detect CRITICAL severity."""
        critical_finding = Finding(
            rule_name="CRITICAL_THREAT",
            severity=Severity.CRITICAL,
            category=RuleCategory.IMPACT,
            title="Critical",
            description="Critical threat",
            evidence={"key": "value"},
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            timestamp=datetime.now(),
            mitre_technique="T1234",
            mitre_tactic="Impact",
        )
        now = datetime.now()
        report = AnalysisReport(
            pcap_filename="test.pcap",
            pcap_hash="abc123",
            analysis_start=now,
            analysis_end=now,
            findings=[critical_finding],
        )
        assert report.has_critical_findings is True

    def test_report_to_dict_json_safe(self) -> None:
        """Report to_dict() must be JSON-serializable."""
        now = datetime.now()
        report = AnalysisReport(
            pcap_filename="test.pcap",
            pcap_hash="abc123",
            analysis_start=now,
            analysis_end=now,
            total_flows=10,
            total_packets=1000,
        )
        d = report.to_dict()
        json.dumps(d)

    def test_report_summary(self) -> None:
        """summary() should return readable string."""
        now = datetime.now()
        report = AnalysisReport(
            pcap_filename="test.pcap",
            pcap_hash="abc123",
            analysis_start=now,
            analysis_end=now,
            total_flows=42,
        )
        summary = report.summary()
        assert "42" in summary
        assert "Flows" in summary

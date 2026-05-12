import pytest
from datetime import datetime, timedelta
from pathlib import Path

from core.models import Flow, Protocol, Finding, Severity, RuleCategory
from detection.rules.port_scan import PortScanRule
from detection.rules.beaconing import BeaconingRule
from detection.rules.dns_tunnel import DNSTunnelingRule
from detection.rules.exfiltration import ExfiltrationRule
from detection.rules.brute_force import BruteForceRule
from detection.engine import DetectionEngine


@pytest.fixture
def sample_flows():
    """Creates sample flows for testing."""
    flows = []
    base_time = datetime(2026, 5, 9, 10, 0, 0)
    
    # Flow 1: Normal HTTP
    flows.append(Flow(
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8",
        src_port=52341,
        dst_port=80,
        protocol=Protocol.HTTP,
        first_seen=base_time,
        last_seen=base_time + timedelta(seconds=5),
        packet_count=10,
        bytes_transferred=5000,
    ))
    
    return flows


class TestPortScanRule:
    
    def test_rule_initialization(self):
        rule = PortScanRule()
        assert rule.rule_name == "PORT_SCAN_DETECTED"
        assert rule.description is not None
    
    def test_no_scan_detected_on_normal_flows(self, sample_flows):
        rule = PortScanRule()
        findings = rule.detect(sample_flows)
        assert len(findings) == 0


class TestBeaconingRule:
    
    def test_rule_initialization(self):
        rule = BeaconingRule()
        assert rule.rule_name == "C2_BEACONING_DETECTED"
    
    def test_no_beacon_on_normal_flows(self, sample_flows):
        rule = BeaconingRule()
        findings = rule.detect(sample_flows)
        assert len(findings) == 0


class TestDNSTunnelingRule:
    
    def test_rule_initialization(self):
        rule = DNSTunnelingRule()
        assert rule.rule_name == "DNS_TUNNELING_DETECTED"
    
    def test_entropy_calculation(self):
        rule = DNSTunnelingRule()
        
        # Low entropy (normal text)
        low = rule._calculate_entropy("google.com")
        
        # High entropy (random)
        high = rule._calculate_entropy("xkj9as8d7f6g5h4j3k2l1m0nopqrstuv")
        
        # Random should have higher entropy
        assert high > low


class TestExfiltrationRule:
    
    def test_rule_initialization(self):
        rule = ExfiltrationRule()
        assert rule.rule_name == "DATA_EXFILTRATION_DETECTED"
    
    def test_no_exfil_on_normal_flows(self, sample_flows):
        rule = ExfiltrationRule()
        findings = rule.detect(sample_flows)
        assert len(findings) == 0


class TestBruteForceRule:
    
    def test_rule_initialization(self):
        rule = BruteForceRule()
        assert rule.rule_name == "BRUTE_FORCE_DETECTED"
    
    def test_service_identification(self):
        rule = BruteForceRule()
        
        assert rule._identify_service(22) == "SSH"
        assert rule._identify_service(21) == "FTP"
        assert rule._identify_service(80) == "HTTP"
        assert rule._identify_service(443) == "HTTPS"


class TestDetectionEngine:
    
    def test_engine_initialization(self):
        engine = DetectionEngine()
        assert len(engine.rules) == 5
    
    def test_engine_runs_all_rules(self, sample_flows):
        engine = DetectionEngine()
        findings = engine.run(sample_flows)
        assert isinstance(findings, list)

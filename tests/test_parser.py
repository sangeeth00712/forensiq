# tests/test_parser.py
# ─────────────────────────────────────────────
# ForensiQ — Unit Tests for PCAP Parser
#
# Run with: pytest tests/test_parser.py -v
# ─────────────────────────────────────────────

import pytest
import tempfile
from pathlib import Path
from datetime import datetime

from core.parser import PcapParser, parse_pcap, PcapParseError
from core.models import Flow, Protocol


@pytest.fixture
def sample_pcap():
    """
    Creates a minimal valid PCAP file for testing.
    
    Format: PCAP header + 1 dummy packet
    """
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        # PCAP header (little-endian)
        pcap_header = b"\xd4\xc3\xb2\xa1"  # Magic number
        pcap_header += b"\x02\x00\x04\x00"  # Version 2.4
        pcap_header += b"\x00\x00\x00\x00"  # Timezone
        pcap_header += b"\x00\x00\x00\x00"  # Timestamp accuracy
        pcap_header += b"\x00\x10\x00\x00"  # Snaplen (4096)
        pcap_header += b"\x01\x00\x00\x00"  # Network (Ethernet)
        
        # Packet header
        pkt_header = b"\x00\x00\x00\x00"  # Timestamp sec
        pkt_header += b"\x00\x00\x00\x00"  # Timestamp usec
        pkt_header += b"\x14\x00\x00\x00"  # Captured length (20)
        pkt_header += b"\x14\x00\x00\x00"  # Original length (20)
        
        # Minimal IP packet
        ip_packet = b"\x45\x00\x00\x14"  # Version, IHL, ToS, Length
        ip_packet += b"\x00\x00\x00\x00"  # ID, Flags, Fragment
        ip_packet += b"\x40\x00\x00\x00"  # TTL, Protocol (none), Checksum
        ip_packet += b"\x7f\x00\x00\x01"  # Source: 127.0.0.1
        ip_packet += b"\x7f\x00\x00\x01"  # Dest: 127.0.0.1
        
        f.write(pcap_header)
        f.write(pkt_header)
        f.write(ip_packet)
        
        temp_path = Path(f.name)
    
    yield temp_path
    temp_path.unlink()


class TestPcapParser:

    def test_parser_initialization(self, sample_pcap):
        """Parser should initialize without errors."""
        parser = PcapParser(sample_pcap)
        assert parser.pcap_file == sample_pcap
        assert parser.packet_count == 0
        assert parser.flow_count == 0

    def test_parser_stats(self, sample_pcap):
        """Parser should track statistics correctly."""
        parser = PcapParser(sample_pcap)
        stats = parser.get_stats()
        assert "packet_count" in stats
        assert "flow_count" in stats
        assert "bytes_total" in stats

    def test_parse_pcap_returns_flows(self, sample_pcap):
        """parse_pcap should return flows and stats."""
        flows, stats = parse_pcap(sample_pcap)
        assert isinstance(flows, list)
        assert isinstance(stats, dict)
        assert "packet_count" in stats

    def test_parse_pcap_handles_invalid_file(self):
        """parse_pcap should raise error for invalid PCAP."""
        invalid_path = Path("/nonexistent/file.pcap")
        with pytest.raises(PcapParseError):
            parse_pcap(invalid_path)


class TestFlowExtraction:

    def test_flow_has_required_fields(self, sample_pcap):
        """Extracted flows should have all required fields."""
        flows, _ = parse_pcap(sample_pcap)
        
        if flows:
            flow = flows[0]
            assert flow.src_ip is not None
            assert flow.dst_ip is not None
            assert flow.protocol is not None
            assert flow.first_seen is not None
            assert flow.last_seen is not None
            assert flow.packet_count > 0

    def test_flow_duration_calculated(self, sample_pcap):
        """Flow duration should be calculable."""
        flows, _ = parse_pcap(sample_pcap)
        
        if flows:
            flow = flows[0]
            assert flow.duration_seconds >= 0.0

    def test_flow_is_serializable(self, sample_pcap):
        """Flows should be convertible to JSON."""
        import json
        flows, _ = parse_pcap(sample_pcap)
        
        if flows:
            flow = flows[0]
            json_str = json.dumps(flow.to_dict())
            assert json_str is not None

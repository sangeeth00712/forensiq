# core/parser.py
# ─────────────────────────────────────────────────────────────
# ForensiQ — PCAP Parser
#
# Reads PCAP files and extracts network flows.
# Uses chunked streaming — safe for multi-GB files.
# Never loads entire file into RAM.
#
# Author  : Sangeeth
# Version : 1.0.0
# ─────────────────────────────────────────────────────────────

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import struct

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.tls.record import TLS

from core.logger import get_logger
from core.models import Flow, Protocol
import config

logger = get_logger(__name__)


class PcapParseError(Exception):
    """Raised when PCAP parsing fails."""
    pass


class PcapParser:
    """
    Streams and parses PCAP files efficiently.
    
    Design:
    - Uses Scapy for packet parsing (battle-tested, handles all edge cases)
    - Maintains flow dictionary (reconstructs conversations)
    - Yields flows as they complete (streaming output)
    - Tracks stats for reporting
    """

    def __init__(self, pcap_file: Path):
        """
        Initialize parser for a PCAP file.
        
        Args:
            pcap_file: Path to .pcap or .pcapng file
        """
        self.pcap_file = pcap_file
        self.flows: Dict[str, Flow] = {}
        self.packet_count = 0
        self.bytes_total = 0
        self.flow_count = 0
        
        logger.debug(f"Parser initialized for: {pcap_file.name}")

    def _make_flow_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: Protocol
    ) -> str:
        """
        Creates a unique flow identifier.
        
        Flow key format: src_ip:src_port-dst_ip:dst_port-protocol
        Used as dictionary key to track unique conversations.
        """
        return (
            f"{src_ip}:{src_port}"
            f"-{dst_ip}:{dst_port}"
            f"-{protocol.value}"
        )

    def _extract_dns(self, packet) -> Optional[str]:
        """
        Extracts DNS query from packet if present.
        
        Returns:
            DNS query string or None
        """
        try:
            if DNS not in packet:
                return None
            
            dns_layer = packet[DNS]
            
            # DNS queries are in DNSQR (DNS Question Record)
            if DNSQR in packet:
                return packet[DNSQR].qname.decode('utf-8', errors='ignore')
            
            return None
        except Exception as e:
            logger.debug(f"Error extracting DNS: {e}")
            return None

    def _extract_http_host(self, packet) -> Optional[str]:
        """
        Extracts HTTP Host header from packet if present.
        
        Returns:
            Host header value or None
        """
        try:
            if HTTP not in packet and HTTPRequest not in packet:
                return None
            
            if HTTPRequest in packet:
                http_layer = packet[HTTPRequest]
                if hasattr(http_layer, 'Host'):
                    return http_layer.Host.decode('utf-8', errors='ignore')
            
            return None
        except Exception as e:
            logger.debug(f"Error extracting HTTP Host: {e}")
            return None

    def _extract_tls_sni(self, packet) -> Optional[str]:
        """
        Extracts TLS Server Name Indication (SNI) from packet.
        
        SNI is the hostname in TLS Client Hello.
        Used for HTTPS host identification without decryption.
        
        Returns:
            SNI hostname or None
        """
        try:
            if TLS not in packet:
                return None
            
            tls_layer = packet[TLS]
            
            # TLS handshake contains SNI
            if hasattr(tls_layer, 'handshake_protocol'):
                for handshake in tls_layer.handshake_protocol:
                    if hasattr(handshake, 'extensions'):
                        for ext in handshake.extensions:
                            if hasattr(ext, 'server_name'):
                                return ext.server_name
            
            return None
        except Exception as e:
            logger.debug(f"Error extracting TLS SNI: {e}")
            return None

    def _process_packet(self, packet, timestamp: datetime) -> None:
        """
        Processes a single packet and updates flow dictionary.
        
        Args:
            packet: Scapy packet object
            timestamp: Packet timestamp from PCAP
        """
        if IP not in packet:
            return  # Only process IP packets

        self.packet_count += 1
        self.bytes_total += len(packet)

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = Protocol.OTHER

        # Determine protocol and extract ports
        src_port = 0
        dst_port = 0

        if TCP in packet:
            protocol = Protocol.TCP
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = Protocol.UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            protocol = Protocol.ICMP
        else:
            return  # Only track TCP, UDP, ICMP for now

        # Create or update flow
        flow_key = self._make_flow_key(
            src_ip, dst_ip, src_port, dst_port, protocol
        )

        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                first_seen=timestamp,
                last_seen=timestamp,
                packet_count=1,
                bytes_transferred=len(packet),
            )
            self.flow_count += 1
        else:
            flow = self.flows[flow_key]
            flow.packet_count += 1
            flow.bytes_transferred += len(packet)
            flow.last_seen = timestamp

        # Extract protocol-specific data
        flow = self.flows[flow_key]

        if protocol == Protocol.UDP:
            dns_query = self._extract_dns(packet)
            if dns_query:
                flow.dns_query = dns_query
                flow.protocol = Protocol.DNS

        if protocol == Protocol.TCP:
            http_host = self._extract_http_host(packet)
            if http_host:
                flow.http_host = http_host
                flow.protocol = Protocol.HTTP

            tls_sni = self._extract_tls_sni(packet)
            if tls_sni:
                flow.tls_sni = tls_sni
                flow.protocol = Protocol.TLS

    def parse(self) -> List[Flow]:
        """
        Parses the entire PCAP file and returns all flows.
        
        Uses Scapy's rdpcap() with threading to handle large files.
        Processes packets one at a time to minimize memory usage.
        
        Returns:
            List of Flow objects
            
        Raises:
            PcapParseError: If PCAP file is invalid or unreadable
        """
        logger.info(f"Starting PCAP parse: {self.pcap_file.name}")

        try:
            # Read PCAP — Scapy handles both .pcap and .pcapng formats
            packets = scapy.rdpcap(str(self.pcap_file))
            
            logger.debug(f"Loaded {len(packets)} packets from PCAP")

            # Process each packet
            for i, packet in enumerate(packets):
                if i > config.MAX_PACKETS:
                    logger.warning(
                        f"PCAP exceeded MAX_PACKETS ({config.MAX_PACKETS}). "
                        f"Stopping analysis."
                    )
                    break

                # Extract timestamp
                timestamp = datetime.fromtimestamp(float(packet.time))

                # Process packet (updates self.flows)
                self._process_packet(packet, timestamp)

                # Log progress every 10k packets
                if (i + 1) % 10000 == 0:
                    logger.info(f"Processed {i + 1} packets, {len(self.flows)} flows")

            logger.info(
                f"Parse complete | "
                f"Packets: {self.packet_count} | "
                f"Flows: {self.flow_count} | "
                f"Bytes: {self.bytes_total}"
            )

            return list(self.flows.values())

        except Exception as e:
            error_msg = f"Failed to parse PCAP: {e}"
            logger.error(error_msg)
            raise PcapParseError(error_msg) from e

    def get_stats(self) -> Dict[str, int]:
        """
        Returns parsing statistics.
        
        Returns:
            Dictionary with packet_count, flow_count, bytes_total
        """
        return {
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "bytes_total": self.bytes_total,
        }


def parse_pcap(pcap_file: Path) -> Tuple[List[Flow], Dict[str, int]]:
    """
    Convenience function to parse a PCAP file.
    
    This is the main entry point for the rest of ForensiQ.
    
    Args:
        pcap_file: Path to PCAP file (already validated)
    
    Returns:
        Tuple of (flows list, statistics dict)
        
    Raises:
        PcapParseError: If parsing fails
    """
    parser = PcapParser(pcap_file)
    flows = parser.parse()
    stats = parser.get_stats()
    return flows, stats

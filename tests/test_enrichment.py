import pytest
from datetime import datetime
from pathlib import Path

from core.models import IOC, IOCType, Finding, Severity, RuleCategory
from enrichment.cache import EnrichmentCache
from enrichment.virustotal import VirusTotalClient
from enrichment.mitre import MITREMapping
from enrichment.enricher import Enricher


class TestEnrichmentCache:

    def test_cache_set_and_get(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = Path(f.name)
        
        cache = EnrichmentCache(db_path)
        
        data = {"malicious": True, "vt_score": "45/72"}
        cache.set("192.168.1.1", "ip", data)
        
        result = cache.get("192.168.1.1")
        assert result is not None
        assert result["malicious"] == True
        
        db_path.unlink()

    def test_cache_expiration(self):
        import tempfile
        import time
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = Path(f.name)
        
        # Create cache with 1 second TTL
        cache = EnrichmentCache(db_path)
        cache.ttl = 1
        
        data = {"malicious": True}
        cache.set("192.168.1.1", "ip", data)
        
        # Should exist immediately
        assert cache.get("192.168.1.1") is not None
        
        # Should expire after 2 seconds
        time.sleep(2)
        assert cache.get("192.168.1.1") is None
        
        db_path.unlink()


class TestMITREMapping:

    def test_get_technique(self):
        tech = MITREMapping.get_technique("T1046")
        assert tech is not None
        assert tech["tactic"] == "Discovery"
        assert tech["name"] == "Network Service Discovery"

    def test_get_tactic(self):
        tactic = MITREMapping.get_tactic("T1110")
        assert tactic == "Credential Access"

    def test_all_techniques(self):
        techs = MITREMapping.all_techniques()
        assert len(techs) > 0
        assert "T1046" in techs


class TestEnricher:

    def test_enricher_init(self):
        enricher = Enricher()
        assert enricher.cache is not None
        assert enricher.vt is not None

    def test_is_private_ip(self):
        enricher = Enricher()
        
        assert enricher._is_private_ip("192.168.1.1") == True
        assert enricher._is_private_ip("10.0.0.1") == True
        assert enricher._is_private_ip("127.0.0.1") == True
        assert enricher._is_private_ip("8.8.8.8") == False

    def test_enrich_ioc_private_ip(self):
        enricher = Enricher()
        ioc = IOC(value="192.168.1.1", ioc_type=IOCType.IP)
        
        enricher.enrich_ioc(ioc)
        
        assert ioc.enriched == True
        # Should not query VT for private IPs

    def test_enrich_finding(self):
        enricher = Enricher()
        
        finding = Finding(
            rule_name="TEST",
            severity=Severity.HIGH,
            category=RuleCategory.RECONNAISSANCE,
            title="Test",
            description="Test",
            evidence={"test": "data"},
            src_ip="192.168.1.1",
            dst_ip="8.8.8.8",
            timestamp=datetime.now(),
            mitre_technique="T1046",
            mitre_tactic="Discovery",
        )

        finding.iocs.append(IOC(value="192.168.1.1", ioc_type=IOCType.IP))
        
        enricher.enrich_finding(finding)
        
        # Private IP should be enriched (skipped but marked done)
        assert finding.iocs[0].enriched == True

import requests
import time
from typing import Optional, Dict

import config
from core.logger import get_logger

logger = get_logger(__name__)


class VirusTotalClient:
    """
    VirusTotal API v3 integration.
    
    Free tier: 4 requests per minute
    """

    def __init__(self, api_key: str = None):
        self.api_key = api_key or config.VIRUSTOTAL_API_KEY
        self.base_url = config.VT_BASE_URL
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.last_request_time = 0
        self.min_request_interval = 60 / config.VT_REQUESTS_PER_MINUTE

    def _rate_limit(self) -> None:
        """Enforces rate limit (4 req/min)."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            logger.debug(f"Rate limit: sleeping {sleep_time:.1f}s")
            time.sleep(sleep_time)

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """
        Looks up IP address on VirusTotal.
        
        Args:
            ip: IP address
        
        Returns:
            Dict with VT data or None if error
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None

        try:
            self._rate_limit()
            
            url = f"{self.base_url}/ip_addresses/{ip}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                
                result = {
                    "vt_score": f"{malicious}/{total}",
                    "malicious": malicious > 0,
                    "country": data.get("data", {}).get("attributes", {}).get("country"),
                    "asn": data.get("data", {}).get("attributes", {}).get("asn"),
                }
                
                logger.info(f"VirusTotal lookup {ip}: {result['vt_score']}")
                self.last_request_time = time.time()
                return result
            
            elif response.status_code == 404:
                logger.debug(f"IP {ip} not found in VirusTotal")
                return {"vt_score": "0/0", "malicious": False}
            
            else:
                logger.warning(f"VirusTotal error {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {e}")
            return None

    def lookup_domain(self, domain: str) -> Optional[Dict]:
        """
        Looks up domain on VirusTotal.
        
        Args:
            domain: Domain name
        
        Returns:
            Dict with VT data or None if error
        """
        if not self.api_key:
            return None

        try:
            self._rate_limit()
            
            url = f"{self.base_url}/domains/{domain}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                
                result = {
                    "vt_score": f"{malicious}/{total}",
                    "malicious": malicious > 0,
                }
                
                logger.info(f"VirusTotal lookup {domain}: {result['vt_score']}")
                self.last_request_time = time.time()
                return result
            
            elif response.status_code == 404:
                logger.debug(f"Domain {domain} not found in VirusTotal")
                return {"vt_score": "0/0", "malicious": False}
            
            else:
                logger.warning(f"VirusTotal error {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {e}")
            return None

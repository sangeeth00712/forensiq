import sqlite3
import time
from pathlib import Path
from typing import Optional, Dict, Any

import config
from core.logger import get_logger

logger = get_logger(__name__)


class EnrichmentCache:
    """
    SQLite cache for enrichment data.
    
    Prevents re-querying the same IOC within 24 hours.
    Respects rate limits (4 req/min for VirusTotal).
    """

    def __init__(self, db_path: Path = None):
        self.db_path = db_path or config.CACHE_DB_PATH
        self.ttl = config.CACHE_TTL_SECONDS
        self._init_db()

    def _init_db(self):
        """Creates cache table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ioc_cache (
                    value TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    data TEXT,
                    timestamp INTEGER,
                    expires_at INTEGER
                )
            """)
            conn.commit()
        logger.debug(f"Cache initialized at {self.db_path}")

    def get(self, ioc_value: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves cached enrichment data.
        
        Args:
            ioc_value: IOC value (IP, domain, etc)
        
        Returns:
            Cached data dict or None if expired/missing
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT data FROM ioc_cache WHERE value = ? AND expires_at > ?",
                (ioc_value, int(time.time()))
            )
            row = cursor.fetchone()
        
        if row:
            import json
            data = json.loads(row[0])
            logger.debug(f"Cache HIT: {ioc_value}")
            return data
        
        logger.debug(f"Cache MISS: {ioc_value}")
        return None

    def set(self, ioc_value: str, ioc_type: str, data: Dict[str, Any]) -> None:
        """
        Stores enrichment data in cache.
        
        Args:
            ioc_value: IOC value
            ioc_type: Type (ip, domain, hash)
            data: Enrichment data dict
        """
        import json
        now = int(time.time())
        expires_at = now + self.ttl

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO ioc_cache 
                   (value, ioc_type, data, timestamp, expires_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (ioc_value, ioc_type, json.dumps(data), now, expires_at)
            )
            conn.commit()
        
        logger.debug(f"Cache SET: {ioc_value} (expires in {self.ttl}s)")

    def clear_expired(self) -> None:
        """Removes expired entries from cache."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM ioc_cache WHERE expires_at < ?",
                (int(time.time()),)
            )
            conn.commit()
            deleted = cursor.rowcount
        
        if deleted > 0:
            logger.info(f"Cleared {deleted} expired cache entries")

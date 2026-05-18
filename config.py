# config.py
# ─────────────────────────────────────────────
# ForensiQ — Central Configuration
# Author  : Sangeeth
# Version : 1.0.0
# ─────────────────────────────────────────────

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def _secret(key: str, default: str = "") -> str:
    """Read from st.secrets (Streamlit Cloud) or fall back to env var."""
    try:
        import streamlit as st
        return st.secrets.get(key, os.getenv(key, default))
    except Exception:
        return os.getenv(key, default)

BASE_DIR   = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"
CACHE_DIR  = BASE_DIR / "cache"
LOG_DIR    = BASE_DIR / "logs"

for _dir in [UPLOAD_DIR, OUTPUT_DIR, CACHE_DIR, LOG_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024
ALLOWED_EXTENSIONS  = {".pcap", ".pcapng", ".cap"}
MAX_FILENAME_LENGTH = 255

MAX_PACKETS  = 5_000_000
CHUNK_SIZE   = 10_000
MAX_FLOWS    = 500_000

PORT_SCAN_THRESHOLD        = 15
PORT_SCAN_WINDOW_SECONDS   = 60

BEACON_MIN_CONNECTIONS     = 5
BEACON_INTERVAL_TOLERANCE  = 0.50
BEACON_MIN_INTERVAL_SEC    = 5
BEACON_MAX_INTERVAL_SEC    = 3600

DNS_TUNNEL_QUERY_THRESHOLD = 100
DNS_TUNNEL_MIN_ENTROPY     = 3.5
DNS_TUNNEL_LABEL_LENGTH    = 52

EXFIL_BYTES_THRESHOLD      = 10 * 1024
EXFIL_WINDOW_SECONDS       = 300

BRUTE_FORCE_THRESHOLD      = 20
BRUTE_FORCE_WINDOW_SECONDS = 60

VIRUSTOTAL_API_KEY     = _secret("VIRUSTOTAL_API_KEY")
OTX_API_KEY            = _secret("OTX_API_KEY")
GROQ_API_KEY           = _secret("GROQ_API_KEY")
CACHE_DB_PATH          = CACHE_DIR / "forensiq_cache.db"
CACHE_TTL_SECONDS      = 86_400
VT_REQUESTS_PER_MINUTE = 4
VT_BASE_URL            = "https://www.virustotal.com/api/v3"

PRIVATE_IP_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
]

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE  = LOG_DIR / "forensiq.log"

LLM_MODEL        = "llama-3.1-8b-instant"
LLM_BASE_URL     = "https://api.groq.com/openai/v1"
LLM_MAX_TOKENS   = 1024
LLM_TEMPERATURE  = 0.1
LLM_MAX_FINDINGS = 20

# ForensiQ

**Network threat detection and forensics platform. Upload a PCAP file, get a professional threat analysis report.**

Live demo: https://forensiq-007.streamlit.app

---

## Overview

ForensiQ is an automated network forensics tool that analyzes packet capture (PCAP) files for signs of malicious activity. It runs a multi-stage pipeline — validation, parsing, rule-based detection, threat intelligence enrichment, and AI-generated explanations — and produces a structured report with findings, indicators of compromise, and remediation guidance.

Built as a portfolio project demonstrating applied network security, machine learning, and full-stack Python development.

---

## Features

- Parses `.pcap` and `.pcapng` files up to 500 MB using Scapy
- Five detection rules covering the most common network attack patterns
- ML-based confidence scoring using Isolation Forest anomaly detection
- VirusTotal and OTX threat intelligence enrichment for extracted IOCs
- AI-generated plain-language explanations via Groq LLM (Llama 3)
- Downloadable PDF and JSON reports
- Streamlit web interface with live analysis progress
- MITRE ATT&CK technique mapping for every finding

---

## Detection Rules

| Rule | MITRE Technique | Description |
|---|---|---|
| Port Scan Detection | T1046 | Detects hosts probing more than 15 ports within 60 seconds |
| Brute Force Detection | T1110 | Flags repeated authentication failures from a single source |
| C2 Beacon Detection | T1071 | Identifies periodic check-in traffic consistent with C2 beaconing |
| Data Exfiltration | T1041 | Detects large outbound data transfers to external destinations |
| DNS Tunneling | T1071.004 | Identifies high-entropy, high-volume DNS queries indicative of tunneling |

---

## Architecture

```
PCAP file
    |
    v
Validator          Checks file size, extension, magic bytes, filename safety
    |
    v
Parser             Scapy-based stream parser, reconstructs bidirectional flows
    |
    v
Detection Engine   Runs all rules in parallel, isolates failures per rule
    |
    v
Enricher           Queries VirusTotal and OTX for each extracted IOC
    |
    v
LLM Explainer      Calls Groq API to generate human-readable explanations
    |
    v
Report Generator   Produces PDF (ReportLab) and structured JSON output
```

---

## Quick Start

**Requirements:** Python 3.10+

```bash
# Clone the repository
git clone https://github.com/sangeeth00712/forensiq.git
cd forensiq

# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env and add your VIRUSTOTAL_API_KEY, OTX_API_KEY, GROQ_API_KEY

# Run the Streamlit app locally
streamlit run streamlit_app.py

# Or run analysis from the command line
python main.py path/to/capture.pcap
```

---

## Configuration

All thresholds and API settings are in `config.py`. API keys are loaded from environment variables or Streamlit secrets.

| Variable | Default | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | — | VirusTotal v3 API key |
| `OTX_API_KEY` | — | AlienVault OTX API key |
| `GROQ_API_KEY` | — | Groq API key for LLM explanations |
| `PORT_SCAN_THRESHOLD` | 15 | Unique ports before a scan is flagged |
| `BRUTE_FORCE_THRESHOLD` | 20 | Failed attempts before brute force is flagged |
| `EXFIL_BYTES_THRESHOLD` | 10240 | Outbound bytes threshold for exfiltration detection |
| `BEACON_INTERVAL_TOLERANCE` | 0.50 | Allowed variance in beacon interval timing |

The application works without API keys. Threat intel enrichment and AI explanations are disabled when keys are absent; all detection rules still run.

---

## Project Structure

```
forensiq/
├── streamlit_app.py        Entry point for Streamlit Cloud
├── app.py                  Flask backend (REST API + SSE streaming)
├── main.py                 CLI runner
├── config.py               Central configuration
├── requirements.txt
│
├── core/
│   ├── parser.py           PCAP parser and flow reconstructor
│   ├── validator.py        File validation and sanitization
│   ├── models.py           Flow, Finding, IOC, AnalysisReport dataclasses
│   └── logger.py
│
├── detection/
│   ├── engine.py           Detection engine, rule registration
│   └── rules/              One file per detection rule
│
├── enrichment/
│   ├── virustotal.py       VirusTotal API client with rate limiting
│   ├── otx.py              AlienVault OTX client
│   ├── cache.py            SQLite-backed response cache (24h TTL)
│   └── enricher.py         Orchestrates enrichment across all IOCs
│
├── ai/
│   ├── explainer.py        Groq LLM client
│   ├── prompt_templates.py Per-rule prompt construction
│   └── guardrails.py       Output validation and safety checks
│
├── ml/
│   ├── anomaly.py          Isolation Forest anomaly scorer
│   └── features.py         Flow feature extraction
│
├── output/
│   ├── report.py           PDF report generator (ReportLab)
│   └── json_export.py      Structured JSON export
│
├── ui/
│   └── app.py              Streamlit interface
│
└── website/
    ├── index.html          Web upload interface
    └── docs.html           Project documentation
```

---

## Running Tests

```bash
# Run all tests
pytest tests/

# Run a specific test file
pytest tests/test_rules.py

# Run with coverage
pytest tests/ --cov=. --cov-report=term-missing
```

Tests use synthetic `Flow` objects — no real PCAP file is required for unit tests.

---

## Deploying to Streamlit Cloud

1. Fork or clone this repository to your GitHub account
2. Go to [share.streamlit.io](https://share.streamlit.io) and connect your repo
3. Set the main file to `streamlit_app.py`
4. Add your API keys under Settings > Secrets:

```toml
VIRUSTOTAL_API_KEY = "your_key"
OTX_API_KEY = "your_key"
GROQ_API_KEY = "your_key"
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Web framework | Streamlit, Flask |
| Packet parsing | Scapy |
| Machine learning | scikit-learn (Isolation Forest) |
| LLM | Groq API (Llama 3.1 8B) |
| Threat intel | VirusTotal v3, AlienVault OTX |
| PDF generation | ReportLab |
| Data processing | pandas, numpy |

---

## Author

Built by **Sangeeth** — [github.com/sangeeth00712](https://github.com/sangeeth00712)

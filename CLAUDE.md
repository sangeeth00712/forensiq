# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Setup
pip install -r requirements.txt
cp .env.example .env  # then fill in API keys

# Run analysis on a PCAP file
python3 main.py <path_to_pcap>

# Run all tests
pytest tests/

# Run a single test file or test
pytest tests/test_rules.py
pytest tests/test_rules.py::TestPortScanRule::test_rule_initialization

# Lint and format
flake8 .
black .
```

All tests use synthetic `Flow` objects — no real PCAP file needed for most unit tests.

## Architecture

ForensiQ is a network forensics tool that analyzes PCAP files for threats. The pipeline is linear:

```
PCAP file → validate → parse → detect → [enrich] → output
```

**Data flow in detail:**

1. `core/validator.py` — validates file size, extension, magic bytes; returns `(safe_name, sha256_hash)` or raises `ValidationError`
2. `core/parser.py` (`PcapParser`) — uses Scapy to stream packets in chunks (never loads full file into RAM), reconstructs bidirectional conversations into `Flow` objects keyed by `src_ip:port-dst_ip:port-proto`
3. `detection/engine.py` (`DetectionEngine`) — iterates all registered `BaseRule` subclasses, calling `rule.execute(flows)` on each; failures in a single rule are swallowed and logged so other rules still run
4. Output is an `AnalysisReport` containing all `Finding` objects, serialized to JSON in `outputs/`

**Core models** (`core/models.py`) — these flow through the entire system:
- `Flow` — one reconstructed network conversation; the unit of analysis for all detection rules
- `Finding` — one detected threat; **must** have a non-empty `evidence` dict (enforced in `__post_init__`)
- `IOC` — indicator of compromise extracted from a finding, enriched by threat intel modules
- `AnalysisReport` — aggregates all findings for a PCAP file

**Adding a detection rule:**
Subclass `BaseRule` in `detection/rules/`, implement `rule_name`, `description`, and `detect(flows) -> List[Finding]`. Register the instance in `DetectionEngine.__init__`. The `execute()` wrapper in `BaseRule` handles logging and error isolation — always call `execute()`, never `detect()` directly.

**Thresholds and limits** are all in `config.py` (e.g., `PORT_SCAN_THRESHOLD`, `BRUTE_FORCE_THRESHOLD`). Rules read from `config` directly — no constructor injection.

**Partially implemented modules** (stubs exist but bodies are empty): `enrichment/`, `ml/`, `ai/`, `output/`, `ui/`. The `main.py` pipeline does not yet call enrichment, ML, or the Streamlit UI.

## Environment

API keys are loaded from `.env` via `python-dotenv`. Required keys:
- `VIRUSTOTAL_API_KEY` — used by `enrichment/virustotal.py`
- `OTX_API_KEY` — used by `enrichment/otx.py`
- `GROQ_API_KEY` — used by `ai/explainer.py` (Groq LLM, model `llama3-8b-8192`)

The LLM is accessed through Groq, not Anthropic — the `ai/` module is a separate inference path from the rule-based detection.

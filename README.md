<div align="center">

# ⚡ CTI-Automator: Operational Threat Intelligence

### Private OSINT Ingestion and OpenCTI Automation Pipeline

[![Status](https://img.shields.io/badge/Status-Production--Ready-success?style=for-the-badge&logo=statuspage&logoColor=white)](https://github.com/kta41/CTI-Automator)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-Integration-003B5C?style=for-the-badge&logo=graphql&logoColor=white)](https://www.opencti.io/)
[![AI](https://img.shields.io/badge/Local_AI-Ollama-white?style=for-the-badge&logo=ollama&logoColor=black)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-gray?style=for-the-badge)](LICENSE)

<br/>

### 🛠️ Tech Stack
**Language & Packaging:** Python 3.11+ | pyproject.toml  
**Ingestion & Modeling:** Requests | pdfplumber | Pydantic  
**AI Engine & Orchestration:** Ollama (`qwen`) | FastMCP  
**CTI Export:** pycti (OpenCTI) | PyMISP | STIX 2.1  
**CI/CD & Code Quality:** Ruff | Mypy | Pytest | GitHub Actions  

<br/>

<p align="center">
  A modular and <i>privacy-first</i> <b>Cyber Threat Intelligence (CTI) agent</b>.<br/>
  Designed to ingest raw OSINT, extract actionable Indicators of Compromise (IoCs), and map TTPs directly into <b>OpenCTI</b> using deterministic logic and local AI.
</p>

</div>

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=6,11,20&height=50&section=header" width="100%" />

---

## 🏗️ System Architecture

CTI-Automator operates through a sequential pipeline (Collector -> Parser -> Emitter) to ensure data integrity before injection into defense platforms.

```text
                                  [ Intelligence Sources ]
                             (AlienVault OTX, Abuse.ch, PDF Reports)
                                               │
                                               ▼
                                  ┌────────────────────────┐
                                  │  Collector Module (In) │
                                  │ REST APIs & pdfplumber │
                                  └────────────┬───────────┘
                                               │
                   ┌───────────────────────────┴───────────────────────────┐
                   ▼                                                       ▼
     ┌───────────────────────────┐                           ┌───────────────────────────┐
     │ Deterministic Extraction  │                           │ Semantic Extraction (AI)  │
     │ Regex for IoCs (IP, URL)  │                           │ Ollama (Qwen) via FastMCP │
     │ Cleaning and Defanging    │                           │ MITRE ATT&CK Mapping      │
     └─────────────┬─────────────┘                           └─────────────┬─────────────┘
                   │                                                       │
                   ├────────────────► [ Pydantic Models ] ◄────────────────┤
                   │                  (Unified Structure)                  │
                   ▼                                                       ▼
     ┌───────────────────────────┐                           ┌───────────────────────────┐
     │     OpenCTI Exporter      │                           │    STIX 2.1 Exporter      │
     │  pycti Client / GraphQL   │                           │  Local JSON Generation    │
     └───────────────────────────┘                           └───────────────────────────┘
```

The agent decouples data collection from processing, allowing the integration of multiple sources or destinations without altering the core engine.

---

## 📁 Repository Structure

```text
.
├── src/cti_automator/   # Main source code
│   ├── cli.py           # CLI entrypoint
│   ├── connectors/      # API clients (OTX, ThreatFox)
│   ├── parsers/         # Regular expressions and AI (Defanging)
│   └── emitters/        # OpenCTI clients and STIX exporters
├── tests/               # Unit tests (Pytest)
├── docs/                # Architecture documentation
├── .github/workflows/   # CI/CD: Automated release pipeline
├── pyproject.toml       # Package configuration and dependencies
└── .env.example         # Tokens and configuration template
```

This repository is ready for distribution. The GitHub Actions pipeline will automatically build and generate a *Release* (`.whl` and `.tar.gz`) every time a semantic *tag* is pushed.

---

## 📡 OSINT Connectors & Ingestion

The deterministic ingestion layer is strict and modular. It currently exposes two main clients for continuous OSINT gathering:

- `cti_automator.connectors.OTXClient`: Pulls subscribed pulses from AlienVault OTX.
- `cti_automator.connectors.ThreatFoxClient`: Queries Abuse.ch ThreatFox for active malware infrastructure.

**Under the hood:** Both connectors enforce data integrity via **Pydantic** models. Network failures or malformed upstream API responses are trapped and normalized into a standard `ConnectorError`. 

---

## 🧠 AI-Powered PDF Analysis

The semantic analysis layer is local-first, ensuring sensitive data never leaves your environment:

- `PDFTextExtractor` extracts text with `pdfplumber` and rejects missing, unreadable, empty, or non-PDF documents.
- `OllamaClient` calls the local `/api/generate` endpoint with JSON output enabled and no streaming.
- `PDFAnalyzer` validates the model response with Pydantic, including IoCs, confidence, evidence, rationale, and MITRE ATT&CK technique mappings.

By default, no report content is sent to a remote service. Configure `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `CTI_REQUEST_TIMEOUT`, and `CTI_VERIFY_TLS` using `.env.example`.

*(Optional)* The analyzer can use hosted providers through an OpenAI Chat Completions-compatible adapter. Set `AI_PROVIDER` to `openai` or `groq`, provide `AI_API_KEY`, and configure the endpoint and model:

```dotenv
# OpenAI Configuration
AI_PROVIDER=openai
AI_API_KEY=your-openai-key
AI_BASE_URL=[https://api.openai.com/v1](https://api.openai.com/v1)
AI_MODEL=gpt-4o-mini
```

`AI_API_KEY` is never included in logs or model representations. Hosted providers require explicit opt-in; Ollama remains the privacy-preserving default.

---

## 📦 STIX 2.1 and OpenCTI Export

The platform abstracts complex CTI data structures into standard formats:
- `STIXExporter` converts validated indicators and ATT&CK mappings into a standard STIX 2.1 bundle. 
- `OpenCTIExporter` serializes that bundle and pushes it through `pycti`. 

Configure `OPENCTI_URL`, `OPENCTI_TOKEN`, and `OPENCTI_VERIFY_TLS` before using the adapter.

---

## ⚙️ Configuration & Development

Built with strict typing and modern DevSecOps tools, the local environment is set up as follows:

```bash
# Isolate and install with development tools
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Apply quality checks (dirty code generates unreliable intelligence):

```bash
ruff check src tests  # Linting & Formatting
mypy src              # Strict type checking
pytest                # Test suite
```

---

## 💡 Execution & Usage

<details open>
<summary><b>1. Credentials Configuration</b></summary>

Copy the environment template and insert your OpenCTI and source tokens:
```bash
cp .env.example .env
nano .env
```
Ensure variables are loaded before running the tool (e.g., `set -a; source .env; set +a`). *Note: To maintain container security standards, the package does not load `.env` files automatically internally.*
</details>

<details open>
<summary><b>2. Command Line Interface (CLI)</b></summary>

The installed package exposes the `cti-automator` globally:

```bash
# General help
cti-automator --help

# API Ingestion
cti-automator ingest-otx --modified-since 2026-01-01
cti-automator ingest-threatfox --days 1

# PDF Semantic Analysis & Export
cti-automator analyze-pdf report.pdf
cti-automator export-pdf report.pdf --stix-output report.bundle.json
cti-automator export-pdf report.pdf --opencti
```
</details>

<details open>
<summary><b>3. MCP Server Orchestration</b></summary>

Run the FastMCP server over the default transport to expose tools to local AI agents:

```bash
cti-automator mcp
cti-automator mcp --transport streamable-http
```
The MCP server exposes `analyze_pdf`, `export_pdf_to_stix`, `export_pdf_to_opencti`, `get_otx_pulses`, and `get_threatfox_iocs`. Tools accept file paths and validated arguments.
</details>

---

## 🚀 Creating a Release

The release workflow runs for tags matching `v*`. Before creating one:

```bash
source .venv/bin/activate
ruff check src tests
mypy src
pytest
python -m build
```

Update the project version in `pyproject.toml`, commit the change, and create a semantic version tag:

```bash
git add pyproject.toml README.md src tests
git commit -m "Prepare release v0.2.0"
git push origin main
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

GitHub Actions automatically installs the package, runs validation, builds the wheel and source archive, and publishes both files in a GitHub Release using `softprops/action-gh-release`.

---

<div align="center">

Developed and maintained by **[Tomás Vinuesa Lago](https://github.com/Kta41)**  
*Contributions, suggestions, and feedback are always welcome.*

</div>

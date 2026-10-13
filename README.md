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
The MCP server exposes `analyze_pdf`, `export_pdf_to_stix`, `export_pdf_to_opencti`,
`get_otx_pulses`, `get_threatfox_iocs`, `enrich_indicators`, `push_to_opencti`,
and `ingest_repositories`. Tools accept validated arguments. Existing API tools
accept `opencti=true` and optional `enrich=["virustotal", "shodan"]`.
</details>

---

## Kubernetes native deployment (Phase 6)

The manifests in `k8s/` are standard Kubernetes YAML for K3s. No Argo CD,
CRDs or Kustomize are required. The container runs as UID/GID 10001 with a
read-only root filesystem and a bounded writable `/tmp`.

### Prepare the image

The container workflow builds and validates the image on pull requests and
`main`. Version tags publish `ghcr.io/kta41/cti-automator:<version>` and
`latest` for stable releases, after a disposable Kubernetes smoke test passes.
Make the GHCR package public or configure an `imagePullSecret` for a private
package. For production, set the same immutable version or digest in both
`k8s/04-deployment.yaml` and `k8s/06-cronjob.yaml`; the default `latest` is
only a bootstrap reference, not a guarantee that an image is already published.

For local testing on a single K3s node without a registry:

```bash
docker build -t cti-automator:phase6 .
docker save cti-automator:phase6 -o /tmp/cti-automator-phase6.tar
sudo k3s ctr images import /tmp/cti-automator-phase6.tar
rm /tmp/cti-automator-phase6.tar
```

Set both workload image references to `cti-automator:phase6` before applying.
For a multi-node cluster, import on every schedulable node or use a registry.

### Prepare configuration and secrets

Configure `OLLAMA_BASE_URL` in `k8s/02-configmap.yaml` to the actual reachable
Ollama Service (include its namespace in the DNS name when needed).
The OpenCTI URL must likewise resolve from the pods, not just from your laptop.

`k8s/03-secret.yaml` is a template. Replace its markers in a protected local
copy, never commit actual credentials, and keep filesystem permissions restricted.
Kubernetes Secrets are not encrypted merely because values are base64 encoded:
restrict RBAC and enable encryption at rest for production.
Do not reapply the placeholder template over an existing configured Secret.
The Docker context excludes all Kubernetes manifests and environment files.

```bash
kubectl apply -f k8s/
kubectl -n cti-automator rollout status deployment/cti-automator --timeout=180s
kubectl -n cti-automator get pods,services,cronjobs
```

Resources are numbered so the namespace is created first. To schema-validate
without starting workloads on a fresh cluster, create only the namespace and
then use server-side dry-run:

```bash
kubectl apply -f k8s/00-namespace.yaml
kubectl apply --dry-run=server -f k8s/
```

### Validate MCP and scheduled ingestion

The MCP Service is `ClusterIP`, not a public endpoint. Authentication and
authorization for remote clients remain pending; do not add a public Ingress or
LoadBalancer. Only trusted workloads should have network access to it.

```bash
kubectl -n cti-automator port-forward service/cti-automator 8000:8000
# In another terminal:
curl --fail http://127.0.0.1:8000/healthz
```

`/healthz` reports process responsiveness only; it does not test credentials,
Ollama, the source APIs or OpenCTI. Streamable HTTP MCP is served at `/mcp`.
To validate real ingestion after configuring both source API keys:

```bash
kubectl -n cti-automator create job --from=cronjob/cti-automator-ingest cti-ingest-check
kubectl -n cti-automator wait --for=condition=complete job/cti-ingest-check --timeout=900s
kubectl -n cti-automator logs job/cti-ingest-check
```

The CronJob runs every 30 minutes, forbids overlapping runs and bounds each Job
to 15 minutes. It imports OTX followed by ThreatFox into OpenCTI with
`--opencti`, then analyzes/imports configured repository reports. Import mode
writes only counts to stdout, not IoCs. OpenCTI credentials are therefore
required. If a source fails, the Job fails explicitly and remaining sources
are not queried. STIX indicator, ATT&CK and relationship IDs are deterministic
so retries reuse object identities; actual merge behavior still depends on
the OpenCTI server version and permissions. Indicators without a source time
use the Unix epoch rather than inventing a new observation time on each run.
Unsupported indicator types fail export rather than being silently dropped.

Existing fetch-only behavior is preserved without `--opencti`:

```bash
cti-automator ingest-otx --opencti
cti-automator ingest-threatfox --days 7 --opencti
cti-automator ingest-otx                         # JSON, no OpenCTI import
```

OTX pagination is bounded to 100 pages; ThreatFox accepts 1–7 days and normalizes
`ip:port` to an IP observable, retaining the original port in source metadata.
The container includes the system `libmagic` dependency required by `pycti`.
The exporter requires pycti 6.9.29+ for its validated JSON import/result contract
and reports rejected or omitted objects as errors, not partial successes.
For non-container installations, install the equivalent OS libmagic package
(on Debian: `sudo apt-get install libmagic1`).

Use `kubectl -n cti-automator describe pod <pod>` and
`kubectl -n cti-automator get events --sort-by=.metadata.creationTimestamp`
to diagnose image pull, Secret, configuration and probe failures.

## Optional enrichment (Phase 7)

Enrichment is disabled by default. Using `--enrich` or MCP's provider parameter
explicitly authorizes sending the selected public IoC values to those providers.
Set `VIRUSTOTAL_API_KEY` and/or `SHODAN_API_KEY` as protected environment/Secret
values; they are not part of the ConfigMap.

```bash
cti-automator ingest-threatfox --enrich virustotal --opencti
cti-automator export-pdf report.pdf --enrich virustotal --stix-output report.json
```

VirusTotal supports public IPs, domains and valid MD5/SHA-1/SHA-256 hashes.
Shodan supports IPs only; when both providers are selected, non-IP indicators
go only to VirusTotal. Email addresses, URLs (which can contain PII), private,
loopback and reserved IPs, invalid hashes and internal domains are rejected
**before any network request in the batch**. Configure
`CTI_RESTRICTED_DOMAINS=corp.example,private.example` to block public corporate
domains too. This is a conservative query policy, not the future full DLP module.
Mixed source batches can contain disallowed values: an explicit enrichment
request then fails the whole batch rather than silently excluding indicators.
Use MCP's `enrich_indicators` with a reviewed public subset when needed.

Results preserve provider, retrieval time, result status, confidence and
reference URL; STIX/OpenCTI external references preserve that provenance.
Source confidence is not overwritten by provider scoring.
`CTI_ENRICHMENT_CACHE_TTL` defaults to 3600 seconds; `CTI_ENRICHMENT_RPM` defaults
to 4 requests per provider per minute. The cache is bounded to 1000 entries,
deduplicates queries, and is local to each process (not a cluster-wide quota).
Local budget exhaustion and HTTP 429 raise explicit `QuotaError`; there are no
unbounded retries or silent success fallbacks. HTTP 404 is a cached `not-found`.
The CronJob does not enable enrichment automatically.

## Authorized repository reports (Phase 8)

Telegram ingestion is intentionally deferred. Repository ingestion uses the
GitHub REST API and is restricted to an explicit comma-separated
`CTI_REPOSITORY_ALLOWLIST=owner/repo,another/repo`. `GITHUB_TOKEN` is optional
for public repositories and required for private repositories; use read-only
repository-content permissions. Credentials are never stored in checkpoints.

```bash
export CTI_REPOSITORY_ALLOWLIST=owner/reports
export CTI_REPOSITORY_CHECKPOINT="$HOME/.local/state/cti-automator/repositories.json"
cti-automator ingest-repositories --opencti
```

Only regular UTF-8 `.md`, `.txt` and `.rst` files under `reports/`, `docs/`,
or named `README.md` are accepted. Samples, archives, symlinks and executable
content are not downloaded or executed. A commit snapshot is pinned before
fetching, and Git blob integrity is checked. Defaults: 20 changed documents per
repository/run, 100000 bytes/document, 2 MB/API response. Remaining changed
documents are picked up on subsequent executions. Recursive tree responses
marked truncated fail explicitly rather than reporting partial success.

Documents retain repository, commit, path, digest, source URL and retrieval
time. Text is passed to the validated analysis pipeline as untrusted evidence.
With the default Ollama provider it stays local; selecting a hosted AI provider
explicitly configures remote text processing.

Atomic checkpoints are advanced **after** analysis and optional OpenCTI delivery
succeed; validated analyses are also written with owner-only permissions into
the checkpoint's sibling `.results/` directory before advancing state. Results
therefore survive a later failure or a failed CLI output write. Restrict access
and retention of these files, which contain intelligence data. Completed
documents survive later failures and retries. Fetching a
document does not itself import it. Cross-process file locking rejects
concurrent repository ingestion instead of corrupting state. The shared
`cti-automator-state` PVC persists state for CLI Jobs and MCP. Its `ReadWriteOnce`
access mode suits a single-node K3s; multi-node deployments need compatible
storage/scheduling or a separate checkpoint store. The CronJob enables this
source only when its allowlist is non-empty.

## Operational observability (Phase 9)

Operational events are JSON on **stderr**, leaving CLI JSON/STIX stdout and
MCP stdio intact. `CTI_LOG_LEVEL` controls verbosity. FastMCP 2.14.7+ is required
for the verified runtime contract. MCP errors are masked, framework tracebacks
and HTTP access logs are suppressed, and server banners are disabled.
Each MCP invocation gets a fresh run UUID even within a long-lived CLI server.
Nested operations share a
run UUID; events contain operation, start/end/error, duration, processed count
where available, and exception category. They deliberately omit arguments,
IoCs, report text, tokens and exception messages. Root-logger third-party events
are also formatted without their messages, metadata or tracebacks. Libraries
with independent handlers/banners can still emit separate diagnostics; restrict
access and retention of all pod logs.

`/metrics` exposes Prometheus counters for operations/outcomes, processed items
and quota failures, plus latency histograms with a fixed operation-label set.
It is distinct from `/healthz`; neither endpoint checks business credentials.
Counters are process-local: MCP operations are scraped, while short-lived CLI
Jobs emit JSON events but are not scraped by this static MCP target. Aggregate
Job events in your log backend; no cluster-wide Job metric totals are claimed.

Optional native Kubernetes monitoring, without Prometheus Operator CRDs:

```bash
kubectl apply -f monitoring/
kubectl -n cti-automator rollout status deployment/cti-prometheus
kubectl -n cti-automator port-forward service/cti-prometheus 9090:9090
```

The supplied Prometheus config scrapes the MCP Service and evaluates availability,
error ratio (>20%), quota exhaustion and p95 latency (>120 seconds) alerts.
Edit the ConfigMap thresholds and durations for your environment, then restart
Prometheus to reload. Retention is 7 days/800 MB with ephemeral storage; replace
the data `emptyDir` with a PVC for durable history. Alert rules are evaluated
locally; configure your Alertmanager separately to deliver notifications.
Import `cti-automator.json` from `monitoring/03-dashboard.yaml` into Grafana or
enable its ConfigMap dashboard sidecar, then select the Prometheus datasource.
All monitoring Services remain internal.

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

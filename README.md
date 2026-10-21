<div align="center">

# ⚡ CTI-Automator: Operational Threat Intelligence

### OSINT ingestion, report analysis and OpenCTI automation

[![Status](https://img.shields.io/badge/Status-Development-success?style=for-the-badge&logo=statuspage&logoColor=white)](https://github.com/kta41/CTI-Automator)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-Integration-003B5C?style=for-the-badge&logo=graphql&logoColor=white)](https://www.opencti.io/)
[![AI](https://img.shields.io/badge/Local_AI-Ollama-white?style=for-the-badge&logo=ollama&logoColor=black)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-gray?style=for-the-badge)](LICENSE)

</div>

CTI-Automator collects threat intelligence from AlienVault OTX, Abuse.ch
ThreatFox, PDF reports and authorized GitHub repositories. It validates IoCs
and MITRE ATT&CK mappings, optionally enriches public indicators, and exports
STIX 2.1 bundles to files or OpenCTI.

The same operations are available through a Python CLI and a standalone
FastMCP server. Docker Compose supports scheduled ingestion with optional
profiles for local AI, historical memory and monitoring.

**Privacy-first, not remote-service-free:** Ollama is the default analysis
provider. Hosted AI and VirusTotal/Shodan enrichment require explicit
configuration or invocation. Production credentials, provider quotas and
OpenCTI permissions must be validated in your own environment.

## Contents

- [Architecture and capabilities](#architecture-and-capabilities)
- [Installation and configuration](#installation-and-configuration)
- [Using the CLI](#using-the-cli)
- [Using MCP](#using-mcp)
- [Data protection (DLP)](#data-protection-dlp)
- [Detection as Code](#detection-as-code)
- [Historical memory (RAG)](#historical-memory-rag)
- [SecOps and ChatOps](#secops-and-chatops)
- [Docker Compose deployment](#docker-compose-deployment)
- [Logs, metrics and monitoring](#logs-metrics-and-monitoring)
- [Development and releases](#development-and-releases)

## Architecture and capabilities

```text
OTX / ThreatFox ── API normalization ────────────────────────┐
                                                           │
PDF / authorized repository reports ── Text + AI analysis ──┤
                                                           ▼
                                                Validated Pydantic models
                                                           │
                                            Optional public-IoC enrichment
                                                (VirusTotal / Shodan)
                                                           │
                                              STIX 2.1 → file / OpenCTI

                  CLI / MCP / Compose ingestion loop
                     JSON events + Prometheus metrics
```

The stack uses Python 3.11+, Requests, pdfplumber, Pydantic, Ollama or an
OpenAI-compatible adapter, FastMCP, stix2 and pycti. Ruff, strict mypy, pytest
and GitHub Actions validate the application and its container.

### Structured intelligence

- **OTX:** subscribed pulses, with modification-time filtering and pagination
  bounded to 100 pages.
- **ThreatFox:** recent IoCs from a 1–7 day window. `ip:port` values become IP
  observables; the original value remains in internal source metadata.
- **STIX/OpenCTI:** normalized indicators and ATT&CK mappings become STIX 2.1
  objects with deterministic IDs. Repeated imports reuse those identities;
  actual merge behavior depends on the OpenCTI version and permissions.
  Missing source timestamps use the Unix epoch instead of an invented
  observation time. Unsupported indicator types fail export explicitly.

The OpenCTI adapter uses pycti's JSON import API with a configured timeout and
rejects incomplete or partially rejected imports rather than reporting success.

### Report analysis

PDF extraction rejects missing, unreadable, empty or non-PDF input. Report text
is passed to the configured LLM as untrusted evidence, not instructions.
Pydantic validates the resulting IoCs, confidence, evidence, rationale and
MITRE ATT&CK technique mappings. Treat generated intelligence as analysis
requiring review, not a guarantee that every model conclusion is correct.

Repository ingestion uses the GitHub REST API with an explicit allowlist:

- Only regular UTF-8 `.md`, `.txt` and `.rst` files under `reports/`, `docs/`,
  or the root `README.md` are accepted. Sample/binary directories, archives,
  symlinks and executable files are excluded; fetched content is never executed.
- A commit snapshot is pinned and Git blob integrity is checked. Documents
  retain repository, path, commit, digest, source URL and retrieval time.
- Defaults are 20 changed documents per repository/run, 100000 bytes/document
  and 2 MB/API response. Remaining changes are processed on later runs;
  truncated repository trees fail explicitly.
- Atomic, file-locked checkpoints advance only after successful analysis,
  requested delivery and saving the validated result. Results are stored with
  owner-only permissions in the checkpoint's sibling `.results/` directory.
  Earlier successes survive later failures; concurrent ingestion is rejected.

Telegram ingestion is not currently implemented.

### Optional indicator enrichment

Enrichment is **disabled by default**. `--enrich` or MCP's provider arguments
authorize sending the selected public IoC values to external providers.

VirusTotal supports public IPs, domains and valid MD5/SHA-1/SHA-256 hashes.
Shodan supports IPs only; when both are selected, non-IP indicators go only
to VirusTotal. Results preserve provider, retrieval time, status, confidence
and reference URL. STIX external references retain that provenance; source
confidence is not overwritten.

Before any request in a batch, the query policy rejects email addresses,
URLs, private/reserved IPs, internal or reserved domains, invalid hashes and
type mismatches. Configure restricted corporate domains too. A mixed batch
containing disallowed values fails as a whole; use MCP's `enrich_indicators`
with a reviewed public subset if needed. This policy is not a full DLP module.

The process-local cache has a configurable TTL and a 1000-entry limit.
Queries are deduplicated. Local quota exhaustion and HTTP 429 raise
`QuotaError`; HTTP 404 is a cached `not-found`. There are no unbounded retries
or silent success fallbacks. Budgets are not shared across cluster replicas.

## Installation and configuration

Install from the repository in an isolated Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .

# Required by pycti on Debian; the Docker image already includes it:
sudo apt-get install libmagic1
```

Alternatively, install a wheel from a GitHub Release with `pip` or `pipx`.
The package is not assumed to be available on PyPI.

Copy [the environment template](.env.example), insert your values and load it:

```bash
cp .env.example .env
chmod 600 .env
# Edit .env locally; never commit real credentials.
set -a
source .env
set +a
```

The package reads environment variables; it does **not** automatically load
`.env`. Only source a file you trust.

| Purpose | Environment variables |
|---|---|
| OTX / ThreatFox | `OTX_API_KEY`, `ABUSECH_API_KEY`; optional `OTX_BASE_URL`, `THREATFOX_BASE_URL` |
| OpenCTI import | `OPENCTI_URL`, `OPENCTI_TOKEN` |
| Local analysis | `AI_PROVIDER=ollama`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL` |
| Hosted analysis | `AI_PROVIDER=openai` or `groq`, `AI_API_KEY`, `AI_BASE_URL`, `AI_MODEL` |
| Enrichment credentials | `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY` |
| Enrichment policy | `CTI_RESTRICTED_DOMAINS` (comma-separated), `CTI_ENRICHMENT_CACHE_TTL=3600`, `CTI_ENRICHMENT_RPM=4` |
| Repository access | `CTI_REPOSITORY_ALLOWLIST` (comma-separated `owner/repo`), optional `GITHUB_TOKEN` |
| Repository limits/state | `CTI_REPOSITORY_MAX_FILES=20`, `CTI_REPOSITORY_MAX_BYTES=100000`, `CTI_REPOSITORY_CHECKPOINT=/state/repositories.json` |
| Network and logs | `CTI_REQUEST_TIMEOUT=30`, `CTI_VERIFY_TLS=true`, `CTI_LOG_LEVEL=INFO` |

`OPENCTI_VERIFY_TLS` is a compatibility alias for the shared TLS setting;
when both variables are set, it takes precedence over `CTI_VERIFY_TLS`.
Keep TLS verification enabled outside a controlled test environment.

Ollama is the default and should point to a trusted local service. Selecting a
hosted provider sends report text to that provider. For example:

```dotenv
AI_PROVIDER=openai
AI_API_KEY=your-protected-key
AI_BASE_URL=https://api.openai.com/v1
AI_MODEL=gpt-4o-mini
```

For repository access, use a GitHub token with minimal read-only content
permissions. Public repositories can be queried without a token, subject to
GitHub's unauthenticated rate limits. Checkpoints never store credentials.

## Using the CLI

### Fetch or import API intelligence

```bash
cti-automator --help
cti-automator ingest-otx --modified-since 2026-01-01
cti-automator ingest-threatfox --days 1

cti-automator ingest-otx --opencti
cti-automator ingest-threatfox --days 7 --opencti
```

Without `--opencti`, API commands return normalized JSON. Import mode writes
counts to stdout rather than IoC content.

### Analyze and export reports

```bash
cti-automator analyze-pdf report.pdf
cti-automator export-pdf report.pdf --stix-output report.bundle.json
cti-automator export-pdf report.pdf --opencti

export CTI_REPOSITORY_ALLOWLIST=owner/reports
export CTI_REPOSITORY_CHECKPOINT="$HOME/.local/state/cti-automator/repositories.json"
cti-automator ingest-repositories
cti-automator ingest-repositories --opencti
```

Choose a writable checkpoint location outside the deployment. Fetching or
analyzing
a report does not itself authorize an OpenCTI import. Successfully checkpointed
repository content is not reprocessed automatically; choose a separate state
path if you intentionally need a new processing/delivery pass.

### Request enrichment explicitly

```bash
cti-automator ingest-threatfox --enrich virustotal --opencti
cti-automator export-pdf report.pdf --enrich virustotal --stix-output report.json
```

These commands require the selected provider credentials and a batch that
passes the public-indicator policy described above.

### Data protection (DLP)

Enable configurable PII redaction before any LLM call or embedding:

```bash
export CTI_DLP_ENABLED=true
export CTI_DLP_EMAIL_DOMAINS=corp.example
export CTI_DLP_INTERNAL_CIDRS=10.0.0.0/8,192.168.0.0/16
export CTI_DLP_NAMES="Alice Smith"
export CTI_DLP_ALLOWED_VALUES=203.0.113.7   # public IoCs that must survive
cti-automator analyze-pdf report.pdf
```

Protected values are replaced with stable `<CTI_EMAIL_n>`, `<CTI_IP_n>` and
`<CTI_NAME_n>` placeholders for the whole execution; counts per category are
exported through the `cti_redactions_total` metric without logging any
original value. A sanitization failure blocks the LLM call instead of sending
unprotected text. Detection is heuristic (regex and CIDR membership); review
the residual risk documented for ambiguous names and unusual formats.

### Detection as Code

Generate YARA and SIGMA **proposals** from an analyzed report:

```bash
cti-automator generate-detections report.pdf \
  --yara-dir detections --sigma-dir detections
cti-automator validate-detections detections   # CI GitOps gate
```

Optional pull-request export requires an explicit allowlist and a token;
without `--submit` the exporter only prints a dry-run plan:

```bash
export CTI_DETECTION_PR_ALLOWLIST=acme/detections
export GITHUB_TOKEN=ghp_...
cti-automator generate-detections report.pdf --pr-repo acme/detections
cti-automator generate-detections report.pdf --pr-repo acme/detections --submit
```

Rules always carry `status="proposal"` (YARA) or the
`cti-automator-proposal` marker (SIGMA); merging requires human review
through the `Detection rules GitOps gate` workflow, which validates every
change to [detections/](detections/). Compile YARA rules with `yara` and check
SIGMA rules with `sigma-cli` before deployment. Nothing is deployed
automatically.

### Historical memory (RAG)

Disabled by default; local Qdrant plus local Ollama embeddings keep data on
the host:

```bash
docker run -d -p 6333:6333 qdrant/qdrant
ollama pull nomic-embed-text
export CTI_MEMORY_ENABLED=true
cti-automator memory-remember report.pdf
cti-automator memory-recall "same infrastructure earlier?" --limit 5
```

Chunks carry tenant, source document, techniques and creation time; recall is
tenant-isolated and returns cited fragments. DLP sanitization is applied
before embeddings, retention is enforced with
`CTI_MEMORY_RETENTION_DAYS`, and remote embeddings require the explicit
`CTI_MEMORY_REMOTE_EMBEDDINGS=true` opt-in plus `AI_*` credentials.

### SecOps and ChatOps

Create one idempotent case per report in TheHive or Cortex XSOAR; dry-run is
always available:

```bash
export CTI_THEHIVE_URL=https://thehive.internal
export CTI_THEHIVE_TOKEN=...
cti-automator create-secops-case report.pdf --destination thehive --dry-run
cti-automator create-secops-case report.pdf --destination thehive --severity high
```

Cases are keyed by a deterministic idempotency key (document + indicators +
techniques): retries reconcile ambiguous responses instead of duplicating,
with bounded attempts (`CTI_SECOPS_RETRY_ATTEMPTS`). ChatOps notifications
are deduplicated, HMAC-signed webhooks configured as `name=url` pairs:

```bash
export CTI_CHATOPS_WEBHOOKS='soc=https://hooks.example/abcd'
export CTI_CHATOPS_SECRETS='soc=signing-secret'
cti-automator notify-chatops report.pdf --destination soc --dry-run
cti-automator notify-chatops report.pdf --destination soc
```

HTTPS public destinations require no extra consent; internal or plain-HTTP
hosts must be listed in `CTI_SECOPS_ALLOWED_HOSTS` (SSRF protection). No
automatic response actions are performed.

## Using MCP

```bash
cti-automator mcp
cti-automator mcp --transport streamable-http --host 127.0.0.1 --port 8000
```

The default transport is stdio. HTTP serves MCP at `/mcp`, process health at
`/healthz` and Prometheus metrics at `/metrics`. `--host` and `--port` require
an HTTP transport; ports must be between 1 and 65535.

| Tool | Operation |
|---|---|
| `analyze_pdf` | Return validated PDF intelligence |
| `export_pdf_to_stix` | Return a PDF-derived STIX bundle |
| `export_pdf_to_opencti` | Analyze a PDF and import its bundle |
| `get_otx_pulses` | Fetch pulses; optional `opencti=true` and `enrich` providers |
| `get_threatfox_iocs` | Fetch recent IoCs; optional `opencti=true` and `enrich` providers |
| `enrich_indicators` | Enrich a reviewed list using explicit `providers` |
| `push_to_opencti` | Import normalized indicators |
| `ingest_repositories` | Analyze allowlisted reports; optional `opencti=true` |
| `generate_detections` | Return YARA/SIGMA proposal summaries (no writes) |
| `remember_analysis` | Store one analysis in historical memory |
| `recall_memory` | Recall cited fragments for a query |
| `create_secops_case` | Plan or create a TheHive/XSOAR case; `dry_run` defaults to true |
| `send_chatops_notification` | Plan or send a signed notification; `dry_run` defaults to true |

PDF tools also accept optional `enrich` providers. File paths are resolved on
the server, not on the client: make required reports accessible to that process.

**Remote authentication and authorization are not implemented.** Keep MCP on
localhost or a trusted internal network; do not expose it through a public
Ingress or LoadBalancer.

## Docker Compose deployment

[compose.yaml](compose.yaml) replaces the previous K3s manifests: it runs the
MCP server and a scheduled ingestion loop, with optional profiles for local
AI (`local-ai`), historical memory (`memory`) and monitoring (`monitoring`).

### Prepare the image

The container workflow validates builds on pull requests and `main`. Version
tags publish `ghcr.io/kta41/cti-automator:<version>` and stable `latest` after
validation. Pin an immutable version or digest in `compose.yaml` for
production; the default `latest` is a bootstrap reference. To build locally
instead, change the anchor image to `build: .`:

```bash
docker compose build 2>/dev/null || docker build -t cti-automator:local .
```

### Configure and run

Copy `.env.example` to `.env` and fill real values; never commit it. The
scheduled API import requires `OTX_API_KEY`, `ABUSECH_API_KEY`, `OPENCTI_URL`
and `OPENCTI_TOKEN`. OpenCTI and any hosted AI must resolve from the
containers, not just from your workstation.

```bash
docker compose up -d mcp ingest
docker compose ps
curl --fail http://127.0.0.1:8000/healthz
```

Containers run as UID/GID 10001 with dropped capabilities, read-only root
filesystems, `no-new-privileges` and bounded writable `/tmp`. The MCP port is
published on loopback only — remote authentication is not implemented.

Optional components are enabled with profiles:

```bash
docker compose --profile local-ai up -d      # local Ollama at 127.0.0.1:11434
docker compose --profile memory up -d        # local Qdrant for RAG memory
docker compose --profile monitoring up -d    # Prometheus (9090) + Grafana (3000)
```

The `ingest` service replaces the previous CronJob: it imports OTX, then
ThreatFox, then repository reports if the allowlist is non-empty, every 30
minutes, without enabling enrichment. Repository checkpoints persist in
`./state` (bind mount); back that directory up.

### Check MCP and manual imports

Health checks test process responsiveness, not source APIs, credentials,
Ollama or OpenCTI. The `mcp` service healthcheck polls `/healthz`.

To run an import manually with the same configuration:

```bash
docker compose run --rm ingest sh -c \
  'cti-automator ingest-otx --opencti && cti-automator ingest-threatfox --opencti'
```

For failures, inspect service logs and restart policies:

```bash
docker compose logs -f mcp ingest
docker compose restart ingest
```

## Logs, metrics and monitoring

Operational events are JSON on **stderr**, preserving CLI JSON/STIX stdout
and MCP stdio. `CTI_LOG_LEVEL` controls verbosity. Each MCP invocation gets
a fresh run UUID; nested operations share it. Events record start/end/error,
duration, counts where available and exception category, without arguments,
IoCs, report text, tokens or exception messages.

Root-logger library events omit messages, metadata and tracebacks. MCP errors
are masked; framework tracebacks, HTTP access logs and server banners are
suppressed. Libraries with independent output can still emit diagnostics:
restrict access and retention of all logs and stored analysis artifacts.

`/metrics` exposes counters for operations/outcomes, processed items and quota
failures, plus latency histograms with bounded operation labels. Metrics are
process-local: the static monitoring target scrapes MCP, not short-lived CLI
Jobs. Aggregate Job JSON events in your log backend; these metrics do not
claim cluster-wide Job totals.

[monitoring/](monitoring/) supplies the Prometheus configuration, four alert
rules and a Grafana dashboard used by the Compose `monitoring` profile:

```bash
docker compose --profile monitoring up -d
docker compose logs -f prometheus grafana
```

Prometheus is reachable on `127.0.0.1:9090` and Grafana on `127.0.0.1:3000`
(default password `changeme` — override `GF_SECURITY_ADMIN_PASSWORD` in
`.env`). Alerts cover endpoint unavailability, error ratio above 20%, quota
exhaustion and p95 latency above 120 seconds. Edit thresholds/durations in
[monitoring/rules.yml](monitoring/rules.yml) and restart Prometheus to
reload. Retention is 7 days/800 MB on the `prometheus_data` volume; use a
bind mount for durable history. Configure Alertmanager separately for
notification delivery.

The dashboard is provisioned automatically from
[monitoring/grafana/dashboards/cti-automator.json](monitoring/grafana/dashboards/cti-automator.json)
with the Prometheus datasource. All monitoring ports stay on loopback.

## Development and releases

### Repository layout

```text
src/cti_automator/
  cli.py                CLI entrypoint
  mcp_server.py         MCP tools, health and metrics routes
  config.py, models.py   Runtime configuration and validated models
  connectors/           OTX and ThreatFox HTTP clients
  parsers/, analyzer.py  PDF extraction and report analysis
  llm.py                Local and hosted AI adapters
  enrichment.py         Optional VirusTotal/Shodan queries
  repositories.py       Authorized reports and checkpoints
  exporters/            STIX and OpenCTI delivery
  sanitizer.py          Configurable DLP redaction before LLM/embeddings
  detections.py         YARA/SIGMA proposals, validation and PR export
  memory.py             Qdrant-backed historical memory (RAG)
  secops.py             TheHive/XSOAR cases and signed ChatOps webhooks
  observability.py      Structured events and metrics
tests/                  Regression tests and runtime/alert fixtures
detections/             Committed rule proposals under GitOps review
compose.yaml            Docker Compose deployment (mcp, ingest, profiles)
monitoring/             Prometheus and Grafana configuration for Compose
.github/workflows/      Releases, container, PyPI publishing and rule gates
Dockerfile              Multistage, non-root runtime with libmagic
pyproject.toml          Packaging, dependencies and development tooling
.env.example            Configuration reference
```

Install development dependencies and run checks:

```bash
source .venv/bin/activate
pip install -e '.[dev]'
ruff check src tests
mypy src
pytest
python -m build
```

The verified integration contracts require FastMCP 2.14.7+ and pycti 6.9.29+,
within the major-version bounds declared in the package. Automated tests use
simulated services and the runtime smoke test exercises the real pycti JSON
adapter/splitter with a simulated object importer. Validate real OpenCTI merges,
provider credentials and LLM behavior separately before production use.

For a release, update the project version, validate and commit the intended
changes, then create and push a matching semantic tag such as `v0.2.0`.
Tags matching `v*` trigger package validation/build and a GitHub Release with
wheel and source archive. The container workflow separately publishes validated
images to GHCR.

Optional Python distribution uses the manual `Publish Python distribution`
workflow with PyPI Trusted Publishing (OIDC), minimal permissions, build
provenance attestations, tag/version consistency checks and secret-hygiene
checks on the built artifacts. Rehearse on TestPyPI first (the default
target); promoting to PyPI requires the protected `pypi` environment and
explicit authorization. The base install is fully functional — all
integrations share the same `requests`-based core, so no optional extras are
required at runtime beyond `dev` for development.

---

Developed and maintained by **[Tomás Vinuesa Lago](https://github.com/Kta41)**.
Contributions, suggestions and feedback are welcome.

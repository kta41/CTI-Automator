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
FastMCP server. Docker and native Kubernetes manifests support scheduled
ingestion in K3s without Argo CD or custom resources.

**Privacy-first, not remote-service-free:** Ollama is the default analysis
provider. Hosted AI and VirusTotal/Shodan enrichment require explicit
configuration or invocation. Production credentials, provider quotas and
OpenCTI permissions must be validated in your own environment.

## Contents

- [Architecture and capabilities](#architecture-and-capabilities)
- [Installation and configuration](#installation-and-configuration)
- [Using the CLI](#using-the-cli)
- [Using MCP](#using-mcp)
- [Native Kubernetes deployment](#native-kubernetes-deployment)
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

                  CLI / MCP / scheduled Kubernetes Jobs
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

Choose a writable checkpoint location outside Kubernetes. Fetching or analyzing
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

PDF tools also accept optional `enrich` providers. File paths are resolved on
the server, not on the client: make required reports accessible to that process.

**Remote authentication and authorization are not implemented.** Keep MCP on
localhost or a trusted internal network; do not expose it through a public
Ingress or LoadBalancer.

## Native Kubernetes deployment

[k8s/](k8s/) contains standard manifests for K3s: Namespace, ServiceAccount,
ConfigMap, Secret template, MCP Deployment/Service, ingestion CronJob and a
state PVC. No Argo CD, Kustomize or CRDs are required.

### Prepare the image

The container workflow validates builds on pull requests and `main`. Version
tags publish `ghcr.io/kta41/cti-automator:<version>` and stable `latest` after
validation, including a disposable Kubernetes smoke test. Make the GHCR package
public or configure an `imagePullSecret`. Set the same immutable version or
digest in the Deployment and CronJob for production; the default `latest`
is a bootstrap reference, not a guarantee that an image is already published.

For local testing on a single K3s node:

```bash
docker build -t cti-automator:local .
docker save cti-automator:local -o /tmp/cti-automator-local.tar
sudo k3s ctr images import /tmp/cti-automator-local.tar
rm /tmp/cti-automator-local.tar
```

Set both workload images to `cti-automator:local` before applying. For multiple
nodes, import on every schedulable node or use a registry.

### Configure and apply

Set the actual reachable Ollama endpoint in [the ConfigMap](k8s/02-configmap.yaml).
OpenCTI must also resolve from the pods, not just from your workstation.

[The Secret](k8s/03-secret.yaml) is a template: supply real values in a protected
local copy, never commit them, and never reapply placeholders over a configured
Secret. The scheduled API import requires `OTX_API_KEY`, `ABUSECH_API_KEY`,
`OPENCTI_URL` and `OPENCTI_TOKEN`. Add optional enrichment/GitHub keys only as
needed. Kubernetes Secrets are not encrypted merely by base64 encoding;
restrict RBAC and enable encryption at rest. Docker excludes manifests and
environment files from its build context.

```bash
kubectl apply -f k8s/
kubectl -n cti-automator rollout status deployment/cti-automator --timeout=180s
kubectl -n cti-automator get pods,services,cronjobs,pvc
```

Files are numbered so the namespace is created first. To validate schema without
starting workloads on a fresh cluster:

```bash
kubectl apply -f k8s/00-namespace.yaml
kubectl apply --dry-run=server -f k8s/
```

Pods run as UID/GID 10001 with no mounted ServiceAccount token, dropped
capabilities, a read-only root filesystem and bounded writable `/tmp`.
Startup, readiness and liveness probes use HTTP health checks.

The shared `cti-automator-state` PVC preserves repository checkpoints and
analysis artifacts. Its `ReadWriteOnce` mode suits single-node K3s; multi-node
deployments need compatible storage/scheduling or a separate checkpoint store.
Ensure your cluster has a suitable default StorageClass.

### Check MCP and scheduled imports

The MCP Service is internal (`ClusterIP`):

```bash
kubectl -n cti-automator port-forward service/cti-automator 8000:8000
# In another terminal:
curl --fail http://127.0.0.1:8000/healthz
```

Health checks test process responsiveness, not source APIs, credentials,
Ollama or OpenCTI.

The CronJob runs every 30 minutes, forbids overlap and limits each Job to
15 minutes. It imports OTX, then ThreatFox, then repository reports if the
allowlist is non-empty. It does not enable enrichment automatically. A failure
stops the Job explicitly; subsequent sources are not queried.

To run an import manually after configuring credentials:

```bash
kubectl -n cti-automator create job --from=cronjob/cti-automator-ingest cti-ingest-check
kubectl -n cti-automator wait --for=condition=complete job/cti-ingest-check --timeout=900s
kubectl -n cti-automator logs job/cti-ingest-check
```

For failures, inspect the affected pod and events:

```bash
kubectl -n cti-automator describe pod <pod>
kubectl -n cti-automator get events --sort-by=.metadata.creationTimestamp
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

[monitoring/](monitoring/) supplies optional native Prometheus manifests,
four alert rules and a Grafana dashboard:

```bash
kubectl apply -f monitoring/
kubectl -n cti-automator rollout status deployment/cti-prometheus
kubectl -n cti-automator port-forward service/cti-prometheus 9090:9090
```

Create the application namespace first. Alerts cover endpoint unavailability,
error ratio above 20%, quota exhaustion and p95 latency above 120 seconds.
Edit thresholds/durations in [the monitoring ConfigMap](monitoring/01-config.yaml)
and restart Prometheus to reload. Retention is 7 days/800 MB on ephemeral
storage; use a PVC for durable history. Configure Alertmanager separately
for notification delivery.

Import the `cti-automator.json` entry from [the dashboard ConfigMap](monitoring/03-dashboard.yaml)
into Grafana, or enable a ConfigMap dashboard sidecar, and select the Prometheus
datasource. All monitoring Services remain internal.

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
  observability.py      Structured events and metrics
tests/                  Regression tests and runtime/alert fixtures
k8s/                    Native application manifests
monitoring/             Optional Prometheus and Grafana configuration
.github/workflows/      Package releases and container validation/publication
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
images to GHCR. Public PyPI publication is not configured.

---

Developed and maintained by **[Tomás Vinuesa Lago](https://github.com/Kta41)**.
Contributions, suggestions and feedback are welcome.

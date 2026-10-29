"""Local loopback web interface for CTI Automator (Phase 16)."""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from ipaddress import ip_address
from pathlib import Path
from typing import cast

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from cti_automator.analyzer import PDFAnalyzer
from cti_automator.config import Settings
from cti_automator.connectors import OTXClient, ThreatFoxClient
from cti_automator.detections import generate_sigma_rules, generate_yara_rule
from cti_automator.doctor import run_doctor
from cti_automator.enrichment import EnrichmentService, Provider
from cti_automator.exceptions import CTIAutomatorError
from cti_automator.exporters import OpenCTIExporter, STIXExporter
from cti_automator.models import PDFAnalysis
from cti_automator.secops import CortexXSOARAdapter, TheHiveAdapter, build_case

_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")
_ALLOWED_PROVIDERS: frozenset[Provider] = frozenset({"virustotal", "shodan"})


def is_loopback_host(host: str) -> bool:
    """Allow only loopback addresses for unauthenticated local web UI."""
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _sanitize_filename(name: str) -> str:
    cleaned = _SAFE_FILENAME.sub("_", Path(name).name).strip("._") or "report.pdf"
    if not cleaned.lower().endswith(".pdf"):
        cleaned = f"{cleaned}.pdf"
    return cleaned[:80]


def _check_same_origin(request: Request) -> bool:
    """Reject cross-origin state-changing requests."""
    if request.headers.get("x-cti-ui") != "1":
        return False
    origin = request.headers.get("origin")
    if origin:
        host = request.headers.get("host", "")
        if not (
            origin == f"http://{host}"
            or origin == f"https://{host}"
            or origin.startswith(("http://127.0.0.1", "http://localhost"))
        ):
            return False
    return True


def create_ui_app(settings: Settings | None = None) -> Starlette:
    """Build the local single-origin Starlette application."""
    runtime_settings = settings or Settings.from_env()
    enrichment = EnrichmentService(runtime_settings)

    async def index(request: Request) -> HTMLResponse:
        return HTMLResponse(
            _HTML_PAGE,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; style-src 'unsafe-inline'; "
                    "script-src 'unsafe-inline'; object-src 'none'; "
                    "base-uri 'none'; frame-ancestors 'none'"
                ),
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def status_route(request: Request) -> JSONResponse:
        report = run_doctor(runtime_settings, timeout=1.5)
        return JSONResponse(
            {
                "status": "ok",
                "ai_provider": runtime_settings.ai_provider,
                "ai_model": (
                    runtime_settings.ollama_model
                    if runtime_settings.ai_provider == "ollama"
                    else runtime_settings.ai_model
                ),
                "dlp_enabled": runtime_settings.dlp_enabled,
                "memory_enabled": runtime_settings.memory_enabled,
                "opencti_configured": bool(
                    runtime_settings.opencti_url and runtime_settings.opencti_token
                ),
                "thehive_configured": bool(
                    runtime_settings.thehive_url and runtime_settings.thehive_token
                ),
                "doctor": report.model_dump(mode="json"),
            }
        )

    async def analyze_route(request: Request) -> JSONResponse:
        if not _check_same_origin(request):
            return JSONResponse({"error": "Cross-origin request rejected"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "Invalid JSON request body"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "Request body must be an object"}, status_code=400)
        filename = _sanitize_filename(str(body.get("filename", "report.pdf")))
        encoded = body.get("content_base64")
        if not isinstance(encoded, str) or not encoded.strip():
            return JSONResponse({"error": "Missing PDF base64 payload"}, status_code=400)
        try:
            raw_pdf = base64.b64decode(encoded, validate=True)
        except ValueError:
            return JSONResponse({"error": "Invalid base64 PDF payload"}, status_code=400)
        if len(raw_pdf) > runtime_settings.pdf_max_bytes:
            return JSONResponse(
                {"error": "PDF exceeds configured byte limit"}, status_code=413
            )
        if not raw_pdf.startswith(b"%PDF-"):
            return JSONResponse({"error": "Uploaded file is not a valid PDF"}, status_code=400)
        raw_providers = body.get("enrich", [])
        providers: list[Provider] = []
        if isinstance(raw_providers, list):
            for p in raw_providers:
                if p in _ALLOWED_PROVIDERS:
                    providers.append(cast(Provider, p))
        fd, temp_path_str = tempfile.mkstemp(prefix="cti-ui-", suffix=".pdf")
        temp_path = Path(temp_path_str)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw_pdf)
            analysis = PDFAnalyzer(runtime_settings).analyze(temp_path)
            analysis = analysis.model_copy(
                update={
                    "source_document": filename,
                    "indicators": enrichment.enrich(analysis.indicators, providers),
                }
            )
            stix_bundle = json.loads(
                cast(
                    str,
                    STIXExporter()
                    .export_analysis(analysis, include_report=True)
                    .serialize(),
                )
            )
            rules = []
            try:
                rules.append(generate_yara_rule(analysis))
                rules.extend(generate_sigma_rules(analysis))
            except CTIAutomatorError:
                pass
            return JSONResponse(
                {
                    "analysis": analysis.model_dump(mode="json"),
                    "stix_bundle": stix_bundle,
                    "detections": [
                        {**rule.summary(), "content": rule.content} for rule in rules
                    ],
                }
            )
        except (CTIAutomatorError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    async def ingest_route(request: Request) -> JSONResponse:
        if not _check_same_origin(request):
            return JSONResponse({"error": "Cross-origin request rejected"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "Invalid JSON request body"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "Request body must be an object"}, status_code=400)
        source = body.get("source")
        try:
            if source == "otx":
                modified_since = body.get("modified_since")
                pulses = OTXClient(runtime_settings).get_pulses(
                    modified_since=(
                        str(modified_since)
                        if isinstance(modified_since, str) and modified_since.strip()
                        else None
                    )
                )
                return JSONResponse(
                    {
                        "source": "otx",
                        "pulses": [p.model_dump(mode="json") for p in pulses],
                    }
                )
            if source == "threatfox":
                days = int(body.get("days", 1))
                result = ThreatFoxClient(runtime_settings).get_recent_iocs(days=days)
                return JSONResponse(
                    {"source": "threatfox", "result": result.model_dump(mode="json")}
                )
            return JSONResponse({"error": "Unsupported source"}, status_code=400)
        except (CTIAutomatorError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def export_opencti_route(request: Request) -> JSONResponse:
        if not _check_same_origin(request):
            return JSONResponse({"error": "Cross-origin request rejected"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "Invalid JSON request body"}, status_code=400)
        if not isinstance(body, dict) or body.get("confirm") is not True:
            return JSONResponse(
                {"error": "Explicit confirmation (confirm=true) is required"},
                status_code=400,
            )
        try:
            analysis = PDFAnalysis.model_validate(body.get("analysis"))
            serialized = OpenCTIExporter(runtime_settings).export_analysis(analysis)
            objects = json.loads(serialized).get("objects", [])
            return JSONResponse({"status": "imported", "objects": len(objects)})
        except (CTIAutomatorError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def secops_case_route(request: Request) -> JSONResponse:
        if not _check_same_origin(request):
            return JSONResponse({"error": "Cross-origin request rejected"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "Invalid JSON request body"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "Request body must be an object"}, status_code=400)
        destination = body.get("destination", "thehive")
        dry_run = bool(body.get("dry_run", True))
        if destination not in {"thehive", "xsoar"}:
            return JSONResponse({"error": "destination must be thehive or xsoar"}, status_code=400)
        try:
            analysis = PDFAnalysis.model_validate(body.get("analysis"))
            case = build_case(analysis)
            adapter: TheHiveAdapter | CortexXSOARAdapter = (
                TheHiveAdapter(runtime_settings)
                if destination == "thehive"
                else CortexXSOARAdapter(runtime_settings)
            )
            delivery = adapter.deliver(case, dry_run=dry_run)
            return JSONResponse(
                {
                    "case": case.payload_summary(),
                    "delivery": delivery.model_dump(mode="json"),
                }
            )
        except (CTIAutomatorError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

    async def health_route(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/", index, methods=["GET"]),
            Route("/healthz", health_route, methods=["GET"]),
            Route("/api/status", status_route, methods=["GET"]),
            Route("/api/analyze-pdf", analyze_route, methods=["POST"]),
            Route("/api/ingest", ingest_route, methods=["POST"]),
            Route("/api/export-opencti", export_opencti_route, methods=["POST"]),
            Route("/api/secops-case", secops_case_route, methods=["POST"]),
        ]
    )


_HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTI-Automator — Local Analyst Console</title>
<style>
  :root {
    --bg: #0b1120;
    --panel: #111827;
    --border: #1f2937;
    --text: #f3f4f6;
    --muted: #9ca3af;
    --accent: #38bdf8;
    --accent-hover: #0284c7;
    --ok: #10b981;
    --warn: #f59e0b;
    --err: #ef4444;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }
  header {
    padding: 1rem 2rem;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
  }
  header h1 { margin: 0; font-size: 1.25rem; color: var(--accent); }
  main { max-width: 1200px; margin: 1.5rem auto; padding: 0 1.5rem; display: grid; gap: 1.5rem; }
  section {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 1.25rem;
  }
  h2 { margin-top: 0; font-size: 1.05rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 600;
  }
  .badge.ok { background: rgba(16,185,129,0.18); color: var(--ok); }
  .badge.warn { background: rgba(245,158,11,0.18); color: var(--warn); }
  .badge.err { background: rgba(239,68,68,0.18); color: var(--err); }
  .controls { display: flex; gap: 0.75rem; flex-wrap: wrap; align-items: center; margin-bottom: 1rem; }
  button, input, select {
    background: #1e293b;
    color: var(--text);
    border: 1px solid #334155;
    padding: 0.45rem 0.85rem;
    border-radius: 0.375rem;
    font-size: 0.9rem;
  }
  button { cursor: pointer; background: var(--accent-hover); border-color: var(--accent); font-weight: 600; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; font-size: 0.88rem; }
  th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); }
  pre {
    background: #090d16;
    padding: 0.75rem;
    border-radius: 0.375rem;
    overflow-x: auto;
    font-size: 0.82rem;
    border: 1px solid var(--border);
  }
  #alert-box { padding: 0.75rem; border-radius: 0.375rem; display: none; margin-bottom: 1rem; }
</style>
</head>
<body>
<header>
  <h1>CTI-Automator Local Console</h1>
  <div id="service-badges" aria-live="polite">Checking local stack...</div>
</header>
<main>
  <div id="alert-box" role="alert"></div>

  <section aria-labelledby="stack-heading">
    <h2 id="stack-heading">1. Stack Health & Recommended Versions (Doctor)</h2>
    <table id="doctor-table">
      <thead>
        <tr><th>Service</th><th>Status</th><th>Recommended Version</th><th>Detected / Guidance</th></tr>
      </thead>
      <tbody></tbody>
    </table>
  </section>

  <section aria-labelledby="pdf-heading">
    <h2 id="pdf-heading">2. PDF Report Analysis, STIX & Detections</h2>
    <form id="pdf-form" class="controls">
      <label for="pdf-file">Report PDF:</label>
      <input type="file" id="pdf-file" accept=".pdf,application/pdf" required>
      <button type="submit" id="analyze-btn">Analyze Report</button>
      <button type="button" id="download-json-btn" disabled>Download Analysis JSON</button>
      <button type="button" id="download-stix-btn" disabled>Download STIX 2.1 Bundle</button>
      <button type="button" id="export-opencti-btn" disabled>Import into OpenCTI</button>
    </form>
    <div id="analysis-summary"></div>
    <input type="search" id="ioc-filter" placeholder="Filter indicators or techniques..." style="width:100%;margin-top:0.5rem;display:none;">
    <table id="ioc-table" style="display:none;">
      <thead><tr><th>Indicator</th><th>Type</th><th>Confidence</th><th>Source</th></tr></thead>
      <tbody></tbody>
    </table>
    <table id="ttp-table" style="display:none;">
      <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Confidence</th><th>Evidence</th></tr></thead>
      <tbody></tbody>
    </table>
    <div id="rules-container"></div>
  </section>

  <section aria-labelledby="ingest-heading">
    <h2 id="ingest-heading">3. OSINT Feed Ingestion (OTX / ThreatFox)</h2>
    <div class="controls">
      <label for="feed-source">Feed:</label>
      <select id="feed-source">
        <option value="threatfox">Abuse.ch ThreatFox</option>
        <option value="otx">AlienVault OTX</option>
      </select>
      <label for="feed-days">Days (ThreatFox):</label>
      <input type="number" id="feed-days" value="1" min="1" max="7" style="width:4.5rem;">
      <button type="button" id="fetch-feed-btn">Fetch Indicators</button>
    </div>
    <pre id="feed-output" style="display:none;"></pre>
  </section>
</main>
<script>
let currentResult = null;

function showAlert(msg, isError) {
  const box = document.getElementById('alert-box');
  box.style.display = 'block';
  box.style.background = isError ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)';
  box.textContent = msg;
}

async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    const badges = document.getElementById('service-badges');
    badges.textContent = '';
    const b1 = document.createElement('span');
    b1.className = 'badge ok';
    b1.textContent = 'AI: ' + data.ai_provider + ' (' + data.ai_model + ')';
    badges.appendChild(b1);

    const tbody = document.querySelector('#doctor-table tbody');
    tbody.textContent = '';
    for (const svc of data.doctor.services) {
      const tr = document.createElement('tr');
      const tdName = document.createElement('td');
      tdName.textContent = svc.service.toUpperCase();
      const tdStatus = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = 'badge ' + (svc.status === 'ok' ? 'ok' : 'warn');
      badge.textContent = svc.status;
      tdStatus.appendChild(badge);
      const tdVer = document.createElement('td');
      tdVer.textContent = svc.recommended_version + ' (' + svc.image + ')';
      const tdGuide = document.createElement('td');
      tdGuide.textContent = svc.status === 'ok'
        ? ('Connected' + (svc.detected_version ? ' v' + svc.detected_version : ''))
        : (svc.install_proposal || '');
      tr.append(tdName, tdStatus, tdVer, tdGuide);
      tbody.appendChild(tr);
    }
  } catch (e) {
    showAlert('Failed to query local status: ' + e, true);
  }
}

document.getElementById('pdf-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const fileInput = document.getElementById('pdf-file');
  if (!fileInput.files.length) return;
  const file = fileInput.files[0];
  const btn = document.getElementById('analyze-btn');
  btn.disabled = true;
  showAlert('Analyzing ' + file.name + '...', false);
  try {
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    const res = await fetch('/api/analyze-pdf', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CTI-UI': '1'},
      body: JSON.stringify({filename: file.name, content_base64: btoa(binary)})
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Analysis failed');
    currentResult = data;
    renderAnalysis(data);
    showAlert('Analysis completed for ' + file.name, false);
  } catch (err) {
    showAlert(err.message, true);
  } finally {
    btn.disabled = false;
  }
});

function renderAnalysis(data) {
  const a = data.analysis;
  const summary = document.getElementById('analysis-summary');
  summary.textContent = 'Summary: ' + a.summary;
  document.getElementById('download-json-btn').disabled = false;
  document.getElementById('download-stix-btn').disabled = false;
  document.getElementById('export-opencti-btn').disabled = false;
  document.getElementById('ioc-filter').style.display = 'block';
  const iocTable = document.getElementById('ioc-table');
  iocTable.style.display = 'table';
  const iocBody = iocTable.querySelector('tbody');
  iocBody.textContent = '';
  for (const ind of a.indicators) {
    const tr = document.createElement('tr');
    for (const val of [ind.value, ind.indicator_type, ind.confidence ?? '-', ind.source]) {
      const td = document.createElement('td');
      td.textContent = String(val);
      tr.appendChild(td);
    }
    iocBody.appendChild(tr);
  }
  const ttpTable = document.getElementById('ttp-table');
  ttpTable.style.display = 'table';
  const ttpBody = ttpTable.querySelector('tbody');
  ttpBody.textContent = '';
  for (const ttp of a.ttps) {
    const tr = document.createElement('tr');
    for (const val of [ttp.technique_id, ttp.technique_name, ttp.tactic, ttp.confidence, ttp.evidence]) {
      const td = document.createElement('td');
      td.textContent = String(val);
      tr.appendChild(td);
    }
    ttpBody.appendChild(tr);
  }
  const rulesDiv = document.getElementById('rules-container');
  rulesDiv.textContent = '';
  for (const rule of (data.detections || [])) {
    const pre = document.createElement('pre');
    pre.textContent = rule.content;
    rulesDiv.appendChild(pre);
  }
}

document.getElementById('ioc-filter').addEventListener('input', (ev) => {
  const q = ev.target.value.toLowerCase();
  for (const row of document.querySelectorAll('#ioc-table tbody tr, #ttp-table tbody tr')) {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  }
});

function downloadBlob(obj, name) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

document.getElementById('download-json-btn').addEventListener('click', () => {
  if (currentResult) downloadBlob(currentResult.analysis, 'analysis.json');
});
document.getElementById('download-stix-btn').addEventListener('click', () => {
  if (currentResult) downloadBlob(currentResult.stix_bundle, 'bundle.stix.json');
});
document.getElementById('export-opencti-btn').addEventListener('click', async () => {
  if (!currentResult) return;
  if (!confirm('Import this STIX bundle into OpenCTI?')) return;
  const res = await fetch('/api/export-opencti', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CTI-UI': '1'},
    body: JSON.stringify({analysis: currentResult.analysis, confirm: true})
  });
  const data = await res.json();
  showAlert(res.ok ? ('Imported ' + data.objects + ' STIX objects into OpenCTI.') : data.error, !res.ok);
});

document.getElementById('fetch-feed-btn').addEventListener('click', async () => {
  const source = document.getElementById('feed-source').value;
  const days = Number(document.getElementById('feed-days').value || 1);
  const out = document.getElementById('feed-output');
  out.style.display = 'block';
  out.textContent = 'Fetching...';
  const res = await fetch('/api/ingest', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CTI-UI': '1'},
    body: JSON.stringify({source, days})
  });
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
});

loadStatus();
</script>
</body>
</html>
"""

# CTI-Automator

Privacy-first Cyber Threat Intelligence ingestion and OpenCTI automation agent.

## Development

Create a local environment and install the package with its development tools:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

Run the quality checks:

```bash
.venv/bin/ruff check src tests
.venv/bin/mypy src
.venv/bin/pytest
```

## Phase 2 connectors

The deterministic ingestion layer exposes:

- `cti_automator.connectors.OTXClient` for subscribed AlienVault OTX pulses.
- `cti_automator.connectors.ThreatFoxClient` for Abuse.ch ThreatFox queries.

Both connectors return validated Pydantic models and convert transport or
malformed-response failures into `ConnectorError`. Configure credentials and
endpoints through the variables shown in `.env.example`; the package does not
load `.env` files automatically.

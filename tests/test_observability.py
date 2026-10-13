import json
import logging

import pytest
from prometheus_client import REGISTRY
from starlette.testclient import TestClient

from cti_automator.config import Settings
from cti_automator.mcp_server import create_mcp_server
from cti_automator.observability import configure_logging, observe


def test_events_correlate_and_do_not_include_arguments_results_or_exception(capsys):
    configure_logging("INFO")

    @observe("analysis")
    def inner(secret):
        return [secret]

    @observe("repository")
    def outer():
        return inner("secret@example.com")

    assert outer() == ["secret@example.com"]
    records = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    assert len(records) == 4
    assert len({record["run_id"] for record in records}) == 1
    assert records[-1]["count"] == 1
    assert records[-1]["duration_seconds"] >= 0
    assert "secret" not in json.dumps(records)

    @observe("opencti")
    def failing():
        raise ValueError("token=secret@example.com and confidential report")

    with pytest.raises(ValueError):
        failing()
    output = capsys.readouterr()
    assert output.out == ""
    events = [json.loads(line) for line in output.err.splitlines()]
    assert events[-1]["event"] == "error"
    assert events[-1]["error_category"] == "ValueError"
    assert events[-1]["run_id"] != records[0]["run_id"]
    assert "confidential" not in output.err
    assert "secret@" not in output.err


def test_error_metrics_have_fixed_labels_and_no_sensitive_values():
    configure_logging("ERROR")
    labels = {"operation": "analysis", "outcome": "error"}
    before = REGISTRY.get_sample_value("cti_operations_total", labels) or 0

    @observe("analysis")
    def failure():
        raise ValueError("secret")

    with pytest.raises(ValueError):
        failure()
    assert REGISTRY.get_sample_value("cti_operations_total", labels) == before + 1
    with pytest.raises(ValueError, match="Unregistered"):
        observe("secret@example.com")


def test_metrics_and_health_are_separate_and_content_free():
    server = create_mcp_server(Settings())
    with TestClient(server.http_app()) as client:
        health = client.get("/healthz")
        metrics = client.get("/metrics")
    assert health.json() == {"status": "ok"}
    assert metrics.status_code == 200
    assert "text/plain" in metrics.headers["content-type"]
    assert "cti_operations_total" in metrics.text
    assert 'le="120.0"' in metrics.text
    assert 'le="240.0"' in metrics.text
    assert "secret@example.com" not in metrics.text
    assert "confidential report" not in metrics.text


def test_log_levels_are_validated_and_honored(capsys):
    with pytest.raises(ValueError, match="CTI_LOG_LEVEL"):
        configure_logging("invalid")
    configure_logging("WARNING")

    @observe("analysis")
    def success():
        return []

    success()
    assert capsys.readouterr().err == ""


def test_vendor_messages_metadata_and_tracebacks_are_not_logged(capsys):
    configure_logging("INFO")
    try:
        raise ValueError("confidential-token")
    except ValueError:
        logging.getLogger("api").error(
            "report email=private@example.com",
            extra={"attributes": {"token": "confidential-token"}},
            exc_info=True,
        )
    output = capsys.readouterr()
    event = json.loads(output.err)
    assert event["event"] == "library"
    assert "private@" not in output.err
    assert "confidential-token" not in output.err


def test_mcp_invocations_have_distinct_correlations_within_server_scope(capsys):
    configure_logging()

    @observe("analysis")
    def child():
        return []

    @observe("mcp", new_run=True)
    def tool():
        return child()

    @observe("cli")
    def server_scope():
        tool()
        tool()

    server_scope()
    records = [json.loads(line) for line in capsys.readouterr().err.splitlines()]
    calls = [
        record["run_id"]
        for record in records
        if record["operation"] == "mcp" and record["event"] == "start"
    ]
    assert len(set(calls)) == 2
    assert {
        record["run_id"] for record in records if record["operation"] == "analysis"
    } == set(calls)

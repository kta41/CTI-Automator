import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def compose() -> dict[str, object]:
    document = yaml.safe_load((ROOT / "compose.yaml").read_text())
    assert isinstance(document, dict)
    return document


def test_kubernetes_artifacts_are_fully_removed():
    assert not (ROOT / "k8s").exists()
    assert not (ROOT / "deploy").exists()
    remaining = sorted(path.name for path in (ROOT / "monitoring").glob("*"))
    assert remaining == ["grafana", "prometheus.yml", "rules.yml"]


def test_compose_defines_hardened_mcp_and_ingest_services():
    services = compose()["services"]
    assert isinstance(services, dict)
    assert {"mcp", "ingest"} <= set(services)
    for name in ("mcp", "ingest"):
        service = services[name]
        assert service["env_file"] == [{"path": ".env", "required": False}]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["user"] == "10001:10001"
    health = services["mcp"]["healthcheck"]["test"]
    assert any("/healthz" in part for part in health)
    ports = services["mcp"]["ports"]
    assert ports == ["127.0.0.1:8000:8000"]


def test_ingest_loop_imports_enabled_sources_without_enrichment():
    ingest = compose()["services"]["ingest"]
    command = ingest["command"]
    joined = " ".join(command)
    assert "ingest-otx --opencti" in joined
    assert "ingest-threatfox --opencti" in joined
    assert "CTI_REPOSITORY_ALLOWLIST" in joined
    assert "ingest-repositories --opencti" in joined
    assert "--enrich" not in joined
    assert "sleep 1800" in joined
    assert ingest["environment"]["CTI_REPOSITORY_CHECKPOINT"] == (
        "/state/repositories.json"
    )
    assert any("./state:/state" in volume for volume in ingest["volumes"])


def test_optional_components_are_gated_by_profiles():
    services = compose()["services"]
    profiles = {name: service.get("profiles") for name, service in services.items()}
    assert profiles["ollama"] == ["local-ai"]
    assert profiles["qdrant"] == ["memory"]
    assert profiles["prometheus"] == ["monitoring"]
    assert profiles["grafana"] == ["monitoring"]
    grafana_ports = services["grafana"]["ports"]
    assert all(port.startswith("127.0.0.1:") for port in grafana_ports)
    prometheus_ports = services["prometheus"]["ports"]
    assert all(port.startswith("127.0.0.1:") for port in prometheus_ports)


def test_monitoring_uses_fixed_metric_names_and_compose_target():
    scrape = yaml.safe_load((ROOT / "monitoring/prometheus.yml").read_text())
    assert scrape["scrape_configs"][0]["static_configs"][0]["targets"] == ["mcp:8000"]
    assert scrape["rule_files"] == ["/etc/prometheus/rules.yml"]
    rules = yaml.safe_load((ROOT / "monitoring/rules.yml").read_text())
    assert len(rules["groups"][0]["rules"]) == 4
    dashboard = json.loads(
        (ROOT / "monitoring/grafana/dashboards/cti-automator.json").read_text()
    )
    assert len(dashboard["panels"]) == 4
    expressions = {
        target["expr"]
        for panel in dashboard["panels"]
        for target in panel["targets"]
    }
    assert any("cti_operations_total" in expr for expr in expressions)
    datasources = yaml.safe_load(
        (
            ROOT / "monitoring/grafana/provisioning/datasources/prometheus.yml"
        ).read_text()
    )
    assert datasources["datasources"][0]["url"] == "http://prometheus:9090"
    providers = yaml.safe_load(
        (
            ROOT / "monitoring/grafana/provisioning/dashboards/cti.yml"
        ).read_text()
    )
    assert providers["providers"][0]["options"]["path"] == (
        "/var/lib/grafana/dashboards"
    )

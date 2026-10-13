import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_cron_imports_each_enabled_source_and_persists_checkpoints():
    cron = yaml.safe_load((ROOT / "k8s/06-cronjob.yaml").read_text())
    pod = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    command = pod["containers"][0]["args"][0]
    assert "ingest-otx --opencti" in command
    assert "ingest-threatfox --opencti" in command
    assert "CTI_REPOSITORY_ALLOWLIST" in command
    assert "ingest-repositories --opencti" in command
    assert "--enrich" not in command
    assert any(
        volume.get("persistentVolumeClaim", {}).get("claimName")
        == "cti-automator-state"
        for volume in pod["volumes"]
    )
    assert cron["spec"]["jobTemplate"]["spec"]["activeDeadlineSeconds"] == 900


def test_monitoring_is_native_and_dashboards_use_fixed_metric_names():
    resources = [
        document
        for path in (ROOT / "monitoring").glob("*.yaml")
        for document in yaml.safe_load_all(path.read_text())
    ]
    assert all(
        resource["kind"] in {"Deployment", "Service", "ConfigMap"}
        for resource in resources
    )
    dashboard = next(
        resource
        for resource in resources
        if resource["metadata"]["name"] == "cti-grafana-dashboard"
    )
    payload = json.loads(dashboard["data"]["cti-automator.json"])
    assert len(payload["panels"]) == 4
    config = next(
        resource
        for resource in resources
        if resource["metadata"]["name"] == "cti-prometheus-config"
    )
    rules = yaml.safe_load(config["data"]["rules.yml"])
    assert len(rules["groups"][0]["rules"]) == 4
    scrape = yaml.safe_load(config["data"]["prometheus.yml"])
    assert scrape["scrape_configs"][0]["static_configs"][0]["targets"] == [
        "cti-automator.cti-automator.svc:8000"
    ]

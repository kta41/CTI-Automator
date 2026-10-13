import json
from unittest.mock import Mock

import requests

from cti_automator.config import Settings
from cti_automator.connectors import OTXClient, ThreatFoxClient
from cti_automator.exporters.opencti import OpenCTIExporter


def response(payload):
    result = Mock(spec=requests.Response)
    result.json.return_value = payload
    return result


def test_api_to_stix_to_importer_end_to_end_with_idempotent_retry():
    session = Mock(spec=requests.Session)
    session.request.side_effect = [
        response(
            {
                "results": [
                    {
                        "id": "pulse",
                        "name": "Report",
                        "indicators": [
                            {"id": "ioc", "indicator": "8.8.8.8", "type": "IPv4"},
                        ],
                    }
                ],
            }
        ),
        response(
            {
                "query_status": "ok",
                "data": [{"id": 1, "ioc": "1.1.1.1:443", "ioc_type": "ip:port"}],
            }
        ),
    ]
    settings = Settings(otx_api_key="fake-key", abusech_api_key="fake-key")
    pulses = OTXClient(settings, session=session).get_pulses()
    result = ThreatFoxClient(settings, session=session).get_recent_iocs()
    batch = (*pulses[0].indicators, *result.indicators)
    imported = {}
    client = Mock()

    def import_bundle(bundle, *, update):
        for item in json.loads(bundle)["objects"]:
            imported[item["id"]] = item
        return ([{"id": item["id"]} for item in json.loads(bundle)["objects"]], [])

    client.stix2.import_bundle_from_json.side_effect = import_bundle
    exporter = OpenCTIExporter(settings, client=client)
    exporter.export_indicators(batch)
    exporter.export_indicators(batch)
    assert len(imported) == 2
    assert all(item["type"] == "indicator" for item in imported.values())
    assert ":443" not in json.dumps(imported)
    assert "fake-key" not in json.dumps(imported)


def test_opencti_configuration_is_forwarded_with_timeout(monkeypatch):
    import sys
    from types import SimpleNamespace

    client = Mock()
    factory = Mock(return_value=client)
    monkeypatch.setitem(sys.modules, "pycti", SimpleNamespace(OpenCTIApiClient=factory))
    settings = Settings(
        opencti_url="http://opencti:8080", opencti_token="fake-key", request_timeout=2.5
    )
    OpenCTIExporter(settings)
    factory.assert_called_once_with(
        "http://opencti:8080", "fake-key", ssl_verify=True, requests_timeout=3
    )

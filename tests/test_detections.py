from unittest.mock import Mock

import pytest
import requests

from cti_automator.config import Settings
from cti_automator.detections import (
    DetectionRule,
    FileDetectionExporter,
    GitHubPullRequestExporter,
    generate_sigma_rules,
    generate_yara_rule,
    validate_directory,
    validate_rule,
)
from cti_automator.exceptions import DetectionRuleError
from cti_automator.models import (
    Indicator,
    IndicatorType,
    IntelligenceSource,
    PDFAnalysis,
    TTPMapping,
)


def analysis() -> PDFAnalysis:
    return PDFAnalysis(
        summary="Ransomware report with several indicators.",
        source_document="report.pdf",
        indicators=(
            Indicator(
                value="d41d8cd98f00b204e9800998ecf8427e",
                indicator_type=IndicatorType.FILE_HASH_MD5,
                source=IntelligenceSource.PDF_REPORT,
                confidence=90,
            ),
            Indicator(
                value="evil.example",
                indicator_type=IndicatorType.DOMAIN,
                source=IntelligenceSource.PDF_REPORT,
            ),
            Indicator(
                value="8.8.8.8",
                indicator_type=IndicatorType.IPV4,
                source=IntelligenceSource.PDF_REPORT,
            ),
        ),
        ttps=(
            TTPMapping(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                tactic="Execution",
                rationale="Report shows scripted execution",
                evidence="runs cmd.exe scripts",
                confidence=80,
            ),
        ),
    )


def test_yara_rule_is_a_valid_proposal_with_traceability() -> None:
    rule = generate_yara_rule(analysis())
    assert rule.status == "proposal"
    assert 'status = "proposal"' in rule.content
    assert "d41d8cd98f00b204e9800998ecf8427e" in rule.content
    assert "evil.example" in rule.content
    assert "T1059" in rule.content
    assert rule.rule_id in rule.content
    validate_rule(rule)


def test_yara_rule_ids_are_deterministic() -> None:
    first = generate_yara_rule(analysis())
    second = generate_yara_rule(analysis())
    assert first.rule_id == second.rule_id
    assert first.content.splitlines()[0] == second.content.splitlines()[0]


def test_yara_generation_requires_usable_indicators() -> None:
    empty = PDFAnalysis(summary="s", source_document="x.pdf", indicators=(), ttps=())
    with pytest.raises(DetectionRuleError):
        generate_yara_rule(empty)


def test_sigma_rules_group_by_indicator_type_and_validate() -> None:
    import yaml

    rules = generate_sigma_rules(analysis())
    groups = {rule.filename.split("_")[-2] for rule in rules}
    assert groups == {"domain", "hash", "ip"}
    for rule in rules:
        document = yaml.safe_load(rule.content)
        assert document["custom"] == "cti-automator-proposal"
        assert document["tags"] == ["attack.t1059"]
        assert document["detection"]["condition"] == "selection"
        validate_rule(rule)


@pytest.mark.parametrize(
    "content",
    [
        'rule bad {\n  meta:\n    status = "proposal"\n  condition:\n    any of them\n}',
        'rule CTI_x {\n  meta:\n    status = "active"\n  strings:\n    $s = "a"\n  condition:\n    any of them\n}',
        'rule CTI_x {\n  strings:\n    $s = "a"\n  condition:\n    any of them\n}',
        'rule CTI_x {\n  meta:\n    status = "proposal"\n    id = "1"\n    title = "t"\n    source_document = "d"\n  condition:\n    any of them\n}',
        'rule CTI_x {\n  meta:\n    status = "proposal"\n  strings:\n    $s = "unbalanced\n  condition:\n    any of them\n}',
    ],
)
def test_invalid_yara_proposals_are_rejected(content: str) -> None:
    rule = DetectionRule(
        rule_format="yara",
        rule_id="x",
        filename="x.yar",
        content=content,
        source_document="d",
    )
    with pytest.raises(DetectionRuleError):
        validate_rule(rule)


def test_invalid_sigma_proposals_are_rejected() -> None:
    with pytest.raises(DetectionRuleError):
        validate_rule(
            DetectionRule(
                rule_format="sigma",
                rule_id="x",
                filename="x.yml",
                content="title: t\nstatus: experimental\n",
                source_document="d",
            )
        )
    with pytest.raises(DetectionRuleError):
        validate_rule(
            DetectionRule(
                rule_format="sigma",
                rule_id="x",
                filename="x.yml",
                content="date: 2026-13-99\n",
                source_document="d",
            )
        )


def test_file_exporter_writes_duplicates_and_conflicts(tmp_path):
    rules = (generate_yara_rule(analysis()),)
    exporter = FileDetectionExporter(tmp_path)
    first = exporter.export(rules)
    assert first.written == (rules[0].filename,)
    second = exporter.export(rules)
    assert second.duplicates == (rules[0].filename,)
    (tmp_path / rules[0].filename).write_text("different content", encoding="utf-8")
    third = exporter.export(rules)
    assert third.conflicts == (rules[0].filename,)


def test_file_exporter_requires_existing_directory(tmp_path):
    with pytest.raises(DetectionRuleError):
        FileDetectionExporter(tmp_path / "missing")


def test_validate_directory_reports_errors(tmp_path):
    good = generate_sigma_rules(analysis())[0]
    (tmp_path / good.filename).write_text(good.content, encoding="utf-8")
    (tmp_path / "broken.yml").write_text("title: broken\n", encoding="utf-8")
    count, errors = validate_directory(tmp_path)
    assert count == 2
    assert errors == ["broken.yml: SIGMA rule is missing field 'id'"]


def authorized_settings() -> Settings:
    return Settings(github_token="token", detection_pr_allowlist=("acme/detections",))


def github_response(status=200, payload=None):
    result = Mock(spec=requests.Response)
    result.status_code = status
    result.json.return_value = payload if payload is not None else {}
    return result


def test_pull_request_plan_is_offline_and_safe() -> None:
    session = Mock(spec=requests.Session)
    rules = (generate_yara_rule(analysis()), *generate_sigma_rules(analysis()))
    exporter = GitHubPullRequestExporter(authorized_settings(), session=session)
    plan = exporter.plan(analysis(), rules, "acme/detections")
    session.request.assert_not_called()
    summary = plan.summary()
    assert summary["mode"] == "dry-run"
    assert summary["files"] == [f"detections/{rule.filename}" for rule in rules]
    assert "PROPOSALS" in plan.body


def test_pull_request_plan_requires_allowlisted_repository() -> None:
    exporter = GitHubPullRequestExporter(authorized_settings())
    with pytest.raises(ValueError, match="CTI_DETECTION_PR_ALLOWLIST"):
        exporter.plan(analysis(), (generate_yara_rule(analysis()),), "other/repo")


def test_submit_requires_explicit_token() -> None:
    exporter = GitHubPullRequestExporter(
        Settings(detection_pr_allowlist=("acme/detections",))
    )
    plan = exporter.plan(
        analysis(), (generate_yara_rule(analysis()),), "acme/detections"
    )
    with pytest.raises(ValueError, match="GITHUB_TOKEN"):
        exporter.submit(plan)


def test_submit_skips_duplicate_open_pull_requests() -> None:
    session = Mock(spec=requests.Session)
    session.get.return_value = github_response(
        payload=[{"title": "Detection proposals: report.pdf"}]
    )
    exporter = GitHubPullRequestExporter(authorized_settings(), session=session)
    plan = exporter.plan(
        analysis(), (generate_yara_rule(analysis()),), "acme/detections"
    )
    assert exporter.submit(plan) == "duplicate"
    session.request.assert_not_called()
    session.get.assert_called_once()


def test_submit_creates_branch_files_and_pull_request() -> None:
    session = Mock(spec=requests.Session)
    session.get.return_value = github_response(payload=[])
    session.request.side_effect = [
        github_response(payload={"default_branch": "main"}),
        github_response(payload={"object": {"sha": "a" * 40}}),
        github_response(status=201),
        github_response(status=201),
        github_response(status=201, payload={"html_url": "https://pr/1"}),
    ]
    exporter = GitHubPullRequestExporter(authorized_settings(), session=session)
    rules = (generate_yara_rule(analysis()),)
    plan = exporter.plan(analysis(), rules, "acme/detections")
    assert exporter.submit(plan) == "https://pr/1"
    methods = [call.args[0] for call in session.request.call_args_list]
    assert methods == ["GET", "GET", "POST", "PUT", "POST"]
    put_call = session.request.call_args_list[3]
    assert put_call.args[1].endswith(f"contents/detections/{rules[0].filename}")

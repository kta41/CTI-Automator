"""Conversion of internal CTI models to STIX 2.1."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import NAMESPACE_URL, uuid5

from stix2 import AttackPattern, Bundle, Relationship, Report
from stix2 import Indicator as STIXIndicator

from cti_automator.exceptions import ExportError
from cti_automator.models import Indicator, IndicatorType, PDFAnalysis, TTPMapping


class STIXExporter:
    """Build deterministic STIX 2.1 bundles from normalized intelligence."""

    def export_indicators(self, indicators: Sequence[Indicator]) -> Bundle:
        """Create an idempotent bundle without fabricating a PDF analysis."""
        objects: dict[str, STIXIndicator] = {}
        for item in indicators:
            converted = self._indicator(item)
            previous = objects.get(converted.id)
            if previous is not None:
                fields = dict(previous)
                references = {
                    tuple(sorted(dict(reference).items())): dict(reference)
                    for reference in (
                        *previous.external_references,
                        *converted.external_references,
                    )
                }
                fields["external_references"] = list(references.values())
                labels = sorted(
                    set(getattr(previous, "labels", ()))
                    | set(getattr(converted, "labels", ()))
                )
                if labels:
                    fields["labels"] = labels
                objects[converted.id] = STIXIndicator(**fields)
            else:
                objects[converted.id] = converted
        return Bundle(*objects.values(), allow_custom=True)

    def export_analysis(
        self, analysis: PDFAnalysis, *, include_report: bool = False
    ) -> Bundle:
        """Export indicators and ATT&CK mappings from one PDF analysis."""
        objects: list[object] = []
        indicator_objects: dict[str, STIXIndicator] = {}
        for indicator in analysis.indicators:
            stix_indicator = self._indicator(indicator)
            indicator_objects[indicator.value] = stix_indicator
            objects.append(stix_indicator)

        attack_patterns: dict[str, AttackPattern] = {}
        for ttp in analysis.ttps:
            attack_pattern = self._attack_pattern(ttp)
            attack_patterns[ttp.technique_id] = attack_pattern
            objects.append(attack_pattern)

        for indicator in analysis.indicators:
            for ttp in analysis.ttps:
                objects.append(
                    Relationship(
                        id=f"relationship--{uuid5(NAMESPACE_URL, indicator_objects[indicator.value].id + attack_patterns[ttp.technique_id].id)}",
                        created=datetime(1970, 1, 1, tzinfo=UTC),
                        modified=datetime(1970, 1, 1, tzinfo=UTC),
                        relationship_type="indicates",
                        source_ref=indicator_objects[indicator.value].id,
                        target_ref=attack_patterns[ttp.technique_id].id,
                        description=ttp.rationale,
                    )
                )
        if include_report and objects:
            object_ids = [getattr(item, "id", "") for item in objects]
            objects.append(
                Report(
                    id=f"report--{uuid5(NAMESPACE_URL, f'cti-automator-report|{analysis.source_document}')}",
                    created=datetime(1970, 1, 1, tzinfo=UTC),
                    modified=datetime(1970, 1, 1, tzinfo=UTC),
                    name=f"CTI Report: {analysis.source_document}",
                    description=analysis.summary,
                    published=datetime(1970, 1, 1, tzinfo=UTC),
                    report_types=["threat-report"],
                    object_refs=object_ids,
                )
            )
        return Bundle(*objects, allow_custom=True)

    @staticmethod
    def _indicator(indicator: Indicator) -> STIXIndicator:
        pattern_type = _PATTERN_TYPES.get(indicator.indicator_type)
        if pattern_type is None:
            raise ExportError(
                f"indicator type {indicator.indicator_type.value!r} "
                "cannot be represented as a STIX pattern"
            )
        value = indicator.value
        if indicator.indicator_type in {
            IndicatorType.DOMAIN,
            IndicatorType.FILE_HASH_MD5,
            IndicatorType.FILE_HASH_SHA1,
            IndicatorType.FILE_HASH_SHA256,
        }:
            value = value.lower()
        if indicator.indicator_type in {IndicatorType.IPV4, IndicatorType.IPV6}:
            try:
                address = ip_address(value)
            except ValueError as exc:
                raise ExportError("Invalid IP indicator cannot be exported") from exc
            if (indicator.indicator_type == IndicatorType.IPV4) != (
                address.version == 4
            ):
                raise ExportError("IP indicator type does not match its address")
            value = str(address)
        pattern = f"[{pattern_type} = {_stix_string(value)}]"
        timestamp = indicator.first_seen or datetime(1970, 1, 1, tzinfo=UTC)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        references = [
            {
                "source_name": indicator.source.value,
                "external_id": indicator.source_id or indicator.value,
                **(
                    {"url": indicator.source_id}
                    if indicator.source.value == "repository-report"
                    and indicator.source_id
                    else {}
                ),
            },
            *[
                {
                    "source_name": result.provider,
                    "url": result.reference_url,
                    "description": (
                        f"Retrieved {result.retrieved_at.isoformat()}; "
                        f"confidence={result.confidence}; status={result.status}"
                    ),
                }
                for result in indicator.enrichments
            ],
        ]
        return STIXIndicator(
            id=f"indicator--{uuid5(NAMESPACE_URL, pattern)}",
            created=timestamp,
            modified=timestamp,
            pattern=pattern,
            pattern_type="stix",
            valid_from=timestamp,
            labels=list(indicator.tags) or None,
            confidence=indicator.confidence,
            description=f"Source: {indicator.source.value}",
            external_references=references,
        )

    @staticmethod
    def _attack_pattern(ttp: TTPMapping) -> AttackPattern:
        return AttackPattern(
            id=f"attack-pattern--{uuid5(NAMESPACE_URL, ttp.technique_id)}",
            created=datetime(1970, 1, 1, tzinfo=UTC),
            modified=datetime(1970, 1, 1, tzinfo=UTC),
            name=ttp.technique_name,
            description=f"{ttp.rationale}\nEvidence: {ttp.evidence}",
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": ttp.technique_id,
                    "url": (
                        "https://attack.mitre.org/techniques/"
                        f"{ttp.technique_id.replace('.', '/')}/"
                    ),
                }
            ],
        )


def _stix_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


_PATTERN_TYPES: dict[IndicatorType, str] = {
    IndicatorType.DOMAIN: "domain-name:value",
    IndicatorType.EMAIL: "email-addr:value",
    IndicatorType.FILE_HASH_MD5: "file:hashes.'MD5'",
    IndicatorType.FILE_HASH_SHA1: "file:hashes.'SHA-1'",
    IndicatorType.FILE_HASH_SHA256: "file:hashes.'SHA-256'",
    IndicatorType.IPV4: "ipv4-addr:value",
    IndicatorType.IPV6: "ipv6-addr:value",
    IndicatorType.URL: "url:value",
}

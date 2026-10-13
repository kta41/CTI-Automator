"""Conversion of internal CTI models to STIX 2.1."""

from __future__ import annotations

from stix2 import AttackPattern, Bundle, Relationship
from stix2 import Indicator as STIXIndicator

from cti_automator.exceptions import ExportError
from cti_automator.models import Indicator, IndicatorType, PDFAnalysis, TTPMapping


class STIXExporter:
    """Build deterministic STIX 2.1 bundles from normalized intelligence."""

    def export_analysis(self, analysis: PDFAnalysis) -> Bundle:
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
                        relationship_type="indicates",
                        source_ref=indicator_objects[indicator.value].id,
                        target_ref=attack_patterns[ttp.technique_id].id,
                        description=ttp.rationale,
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
        pattern = f"[{pattern_type}:value = {_stix_string(indicator.value)}]"
        return STIXIndicator(
            pattern=pattern,
            pattern_type="stix",
            valid_from=indicator.first_seen,
            labels=list(indicator.tags) or None,
            confidence=indicator.confidence,
            description=f"Source: {indicator.source.value}",
        )

    @staticmethod
    def _attack_pattern(ttp: TTPMapping) -> AttackPattern:
        return AttackPattern(
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
    IndicatorType.DOMAIN: "domain-name",
    IndicatorType.EMAIL: "email-addr",
    IndicatorType.FILE_HASH_MD5: "file:hashes.MD5",
    IndicatorType.FILE_HASH_SHA1: "file:hashes.SHA-1",
    IndicatorType.FILE_HASH_SHA256: "file:hashes.SHA-256",
    IndicatorType.IPV4: "ipv4-addr",
    IndicatorType.IPV6: "ipv6-addr",
    IndicatorType.URL: "url",
}

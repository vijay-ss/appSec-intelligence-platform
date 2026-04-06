"""
Unit tests for PyFlink stream processing operators.
These test operator logic in isolation — no Flink cluster required.
"""
import json
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from operators.normaliser import NormaliserFlatMap, _severity_from_cvss
from operators.cve_join import _version_is_affected, _check_version_range
from operators.blast_radius_scorer import _tier_from_score, _default_metadata


# ── Normaliser tests ──────────────────────────────────────────────────────────

class TestNormaliser:
    def setup_method(self):
        self.op = NormaliserFlatMap()
        self.op.open(MagicMock())

    def test_valid_osv_event(self):
        event = json.dumps({
            "event_id": "abc", "cve_id": "CVE-2024-1234", "source": "osv",
            "published_at": "2024-01-01T00:00:00Z",
            "ingested_at": "2024-01-01T00:00:00Z",
            "cvss_score": 9.1, "affected_package": "requests", "ecosystem": "pypi",
        })
        results = list(self.op.flat_map(event))
        assert len(results) == 1
        parsed = json.loads(results[0])
        assert parsed["cve_id"] == "CVE-2024-1234"
        assert parsed["severity_tier"] == "CRITICAL"

    def test_malformed_json_dropped(self):
        results = list(self.op.flat_map("not-json"))
        assert results == []

    def test_missing_cve_id_dropped(self):
        event = json.dumps({"source": "osv", "cvss_score": 5.0})
        results = list(self.op.flat_map(event))
        assert results == []

    def test_unknown_source_dropped(self):
        event = json.dumps({"event_id": "x", "cve_id": "CVE-2024-1234", "source": "unknown"})
        results = list(self.op.flat_map(event))
        assert results == []


class TestSeverityFromCVSS:
    def test_critical(self):
        assert _severity_from_cvss(9.0) == "CRITICAL"
        assert _severity_from_cvss(10.0) == "CRITICAL"

    def test_high(self):
        assert _severity_from_cvss(7.0) == "HIGH"
        assert _severity_from_cvss(8.9) == "HIGH"

    def test_medium(self):
        assert _severity_from_cvss(4.0) == "MEDIUM"
        assert _severity_from_cvss(6.9) == "MEDIUM"

    def test_low(self):
        assert _severity_from_cvss(0.0) == "LOW"
        assert _severity_from_cvss(3.9) == "LOW"


# ── CVE join version matching tests ──────────────────────────────────────────

class TestVersionMatching:
    def test_exact_match_in_list(self):
        assert _version_is_affected("2.28.0", ["2.28.0", "2.29.0", "2.30.0"], "") is True

    def test_not_in_list(self):
        assert _version_is_affected("2.32.1", ["2.28.0", "2.29.0"], "") is False

    def test_version_range_less_than(self):
        assert _version_is_affected("2.28.0", [], "< 2.32.0") is True

    def test_version_range_not_affected(self):
        assert _version_is_affected("2.32.1", [], "< 2.32.0") is False

    def test_empty_inputs(self):
        assert _version_is_affected("1.0.0", [], "") is False


class TestVersionComparisonFallback:
    """Tests for the string comparison fallback in _check_version_range."""

    def test_less_than_multi_digit(self):
        """Bug fix: string comparison fails on multi-digit numbers."""
        assert _version_is_affected("2.9.0", [], "< 2.10.0") is True
        assert _version_is_affected("2.10.0", [], "< 2.10.0") is False
        assert _version_is_affected("2.11.0", [], "< 2.10.0") is False

    def test_greater_than_multi_digit(self):
        assert _version_is_affected("2.10.0", [], "> 2.9.0") is True
        assert _version_is_affected("2.9.0", [], "> 2.9.0") is False
        assert _version_is_affected("2.8.0", [], "> 2.9.0") is False

    def test_greater_than_or_equal(self):
        assert _version_is_affected("2.10.0", [], ">= 2.10.0") is True
        assert _version_is_affected("2.9.0", [], ">= 2.10.0") is False

    def test_less_than_or_equal(self):
        assert _version_is_affected("2.10.0", [], "<= 2.10.0") is True
        assert _version_is_affected("2.11.0", [], "<= 2.10.0") is False

    def test_exact_match(self):
        assert _version_is_affected("1.2.3", [], "== 1.2.3") is True
        assert _version_is_affected("1.2.4", [], "== 1.2.3") is False

    def test_not_equal(self):
        assert _version_is_affected("1.2.4", [], "!= 1.2.3") is True
        assert _version_is_affected("1.2.3", [], "!= 1.2.3") is False

    def test_complex_range(self):
        assert _version_is_affected("1.5.0", [], ">= 1.0, < 2.0") is True
        assert _version_is_affected("2.0.0", [], ">= 1.0, < 2.0") is False
        assert _version_is_affected("0.9.0", [], ">= 1.0, < 2.0") is False


# ── Blast radius scorer tests ─────────────────────────────────────────────────

class TestBlastRadiusScorer:
    def test_critical_all_factors(self):
        # CVSS 10 + customer facing + compliance + PII = max score
        score = (1.0 * 0.40) + (1.0 * 0.25) + (1.0 * 0.20) + (1.0 * 0.15)
        assert _tier_from_score(score) == "CRITICAL"

    def test_low_no_factors(self):
        score = (0.3 * 0.40)  # only low CVSS, nothing else
        assert _tier_from_score(score) == "LOW"

    def test_default_metadata_safe(self):
        meta = _default_metadata("unknown-service")
        assert meta["is_customer_facing"] is False
        assert meta["pci_scope"] is False
        assert meta["service_id"] == "unknown-service"

"""Tests for report scoring logic."""

from app.graph.nodes.report_generator import (
    _per_framework_scores,
    _severity_breakdown,
    _weighted_score,
)
from tests.conftest import make_finding, make_mapped_control


class TestSeverityBreakdown:
    def test_empty(self):
        assert _severity_breakdown([]) == {
            "critical": 0, "high": 0, "medium": 0, "low": 0
        }

    def test_single_finding(self):
        f = make_finding(severity="high")
        controls = [make_mapped_control(f)]
        bd = _severity_breakdown(controls)
        assert bd["high"] == 1
        assert bd["critical"] == 0

    def test_multiple_severities(self):
        f1 = make_finding(rule_id="rule.1", severity="critical")
        f2 = make_finding(rule_id="rule.2", severity="low")
        controls = [
            make_mapped_control(f1),
            make_mapped_control(f2),
        ]
        bd = _severity_breakdown(controls)
        assert bd["critical"] == 1
        assert bd["low"] == 1

    def test_deduplicates_same_finding_across_frameworks(self):
        f = make_finding(rule_id="rule.1", severity="high")
        # Same finding mapped to two frameworks
        controls = [
            make_mapped_control(f, framework="soc2"),
            make_mapped_control(f, framework="iso27001"),
        ]
        bd = _severity_breakdown(controls)
        assert bd["high"] == 1  # counted once, not twice


class TestPerFrameworkScores:
    def test_no_controls(self):
        scores = _per_framework_scores([])
        for fw in ("soc2", "iso27001", "gdpr", "dpdp"):
            assert scores[fw] == 100

    def test_critical_deduction(self):
        f = make_finding(rule_id="rule.1", severity="critical")
        controls = [make_mapped_control(f, framework="soc2")]
        scores = _per_framework_scores(controls)
        assert scores["soc2"] == 75  # 100 - 25
        assert scores["iso27001"] == 100  # untouched

    def test_multiple_severities(self):
        f1 = make_finding(rule_id="rule.1", severity="critical")
        f2 = make_finding(rule_id="rule.2", severity="high")
        f3 = make_finding(rule_id="rule.3", severity="medium")
        controls = [
            make_mapped_control(f1, framework="soc2"),
            make_mapped_control(f2, framework="soc2"),
            make_mapped_control(f3, framework="soc2"),
        ]
        scores = _per_framework_scores(controls)
        assert scores["soc2"] == max(0, 100 - 25 - 15 - 7)  # 53


class TestWeightedScore:
    def test_all_perfect(self):
        scores = {"soc2": 100, "iso27001": 100, "gdpr": 100, "dpdp": 100}
        assert _weighted_score(scores) == 100

    def test_soc2_only_affected(self):
        scores = {"soc2": 50, "iso27001": 100, "gdpr": 100, "dpdp": 100}
        expected = round(0.35 * 50 + 0.25 * 100 + 0.25 * 100 + 0.15 * 100)
        assert _weighted_score(scores) == expected

    def test_all_zero(self):
        scores = {"soc2": 0, "iso27001": 0, "gdpr": 0, "dpdp": 0}
        assert _weighted_score(scores) == 0

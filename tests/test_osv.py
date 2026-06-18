"""Tests for OSV severity parsing."""

from app.graph.nodes.osv import _severity


class TestOsvSeverity:
    def test_no_severity(self):
        assert _severity({}) == "medium"

    def test_empty_severity_list(self):
        assert _severity({"severity": []}) == "medium"

    def test_no_score(self):
        assert _severity({"severity": [{}]}) == "medium"

    def test_label_critical(self):
        assert _severity({"severity": [{"score": "CRITICAL"}]}) == "critical"

    def test_label_high(self):
        assert _severity({"severity": [{"score": "HIGH"}]}) == "high"

    def test_label_medium(self):
        assert _severity({"severity": [{"score": "MEDIUM"}]}) == "medium"

    def test_label_low(self):
        assert _severity({"severity": [{"score": "low"}]}) == "low"

    def test_numeric_critical(self):
        assert _severity({"severity": [{"score": "9.5"}]}) == "critical"

    def test_numeric_high(self):
        assert _severity({"severity": [{"score": "7.5"}]}) == "high"

    def test_numeric_medium(self):
        assert _severity({"severity": [{"score": "5.0"}]}) == "medium"

    def test_numeric_low(self):
        assert _severity({"severity": [{"score": "2.0"}]}) == "low"

    def test_cvss_vector(self):
        assert _severity({"severity": [{"score": "7.5/10"}]}) == "high"

    def test_unknown_label(self):
        assert _severity({"severity": [{"score": "unknown"}]}) == "medium"

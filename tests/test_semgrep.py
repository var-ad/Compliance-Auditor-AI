"""Tests for semgrep severity mapping."""

from app.graph.nodes.semgrep import _map_severity


class TestMapSeverity:
    def test_error_maps_to_critical(self):
        assert _map_severity("error") == "critical"

    def test_warning_maps_to_high(self):
        assert _map_severity("warning") == "high"

    def test_inventory_maps_to_low(self):
        assert _map_severity("inventory") == "low"

    def test_info_maps_to_low(self):
        assert _map_severity("info") == "low"

    def test_unknown_severity_maps_to_medium(self):
        assert _map_severity("none") == "medium"

    def test_case_insensitive(self):
        assert _map_severity("ERROR") == "critical"
        assert _map_severity("Warning") == "high"

    def test_empty_string(self):
        assert _map_severity("") == "medium"

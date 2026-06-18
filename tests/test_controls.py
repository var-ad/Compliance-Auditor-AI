"""Tests for compliance control mapping."""

from app.mapper.controls import get_controls


class TestGetControls:
    def test_known_rule_id(self):
        """Direct rule_id in CONTROL_MAP returns its controls."""
        controls = get_controls("github_mfa")
        assert len(controls) == 2  # SOC2 + ISO only (governance finding, no GDPR/DPDP)
        soc2 = [c for c in controls if c["framework"] == "soc2"][0]
        iso = [c for c in controls if c["framework"] == "iso27001"][0]
        assert soc2["control_id"] == "CC6.1"
        assert iso["control_id"] == "A.9.4.1"

    def test_semgrep_rule_hardcoded_password(self):
        controls = get_controls("python.lang.security.audit.hardcoded-password")
        assert len(controls) == 4
        soc2 = [c for c in controls if c["framework"] == "soc2"][0]
        assert soc2["control_id"] == "CC6.1"

    def test_semgrep_rule_sqli(self):
        controls = get_controls("python.lang.security.audit.sqli")
        assert len(controls) == 4
        soc2 = [c for c in controls if c["framework"] == "soc2"][0]
        assert soc2["control_id"] == "CC6.6"

    def test_semgrep_rule_exec(self):
        controls = get_controls("python.lang.security.audit.exec")
        assert len(controls) == 2  # command injection → no GDPR/DPDP
        soc2 = [c for c in controls if c["framework"] == "soc2"][0]
        assert soc2["control_id"] == "CC6.6"

    def test_secret_keyword_fallback(self):
        controls = get_controls("some.random.secret.finding")
        assert len(controls) == 4

    def test_injection_keyword_fallback(self):
        controls = get_controls("audit.detected.sqli.injection")
        assert len(controls) == 4
        soc2 = [c for c in controls if c["framework"] == "soc2"][0]
        assert soc2["control_id"] == "CC6.6"

    def test_crypto_keyword_fallback(self):
        controls = get_controls("audit.detected.weak-crypto")
        assert len(controls) == 4
        soc2 = [c for c in controls if c["framework"] == "soc2"][0]
        assert soc2["control_id"] == "CC6.7"

    def test_fallback_for_unknown(self):
        controls = get_controls("completely.unknown.rule")
        assert len(controls) == 2  # default type → SOC2 + ISO only
        soc2 = [c for c in controls if c["framework"] == "soc2"][0]
        assert soc2["control_id"] == "CC7.1"

    def test_empty_rule_id(self):
        controls = get_controls("")
        assert len(controls) == 2  # default type → SOC2 + ISO only

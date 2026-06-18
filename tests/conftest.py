"""Shared fixtures for compliance auditor tests."""


def make_finding(
    rule_id: str = "test.rule",
    severity: str = "medium",
    description: str = "A test finding",
    tool: str = "semgrep",
) -> dict:
    return {
        "tool": tool,
        "severity": severity,
        "title": rule_id,
        "description": description,
        "file_path": "src/main.py",
        "rule_id": rule_id,
    }


def make_mapped_control(
    finding: dict,
    framework: str = "soc2",
    control_id: str = "CC6.1",
    control_name: str = "Logical Access Controls",
    explanation: str = "Test explanation",
) -> dict:
    return {
        "finding": finding,
        "framework": framework,
        "control_id": control_id,
        "control_name": control_name,
        "explanation": explanation,
    }

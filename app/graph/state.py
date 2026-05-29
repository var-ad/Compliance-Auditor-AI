import operator
from typing import Annotated, TypedDict


class Finding(TypedDict):
    tool: str
    severity: str
    title: str
    description: str
    file_path: str | None
    rule_id: str | None


class MappedControl(TypedDict):
    finding: Finding
    framework: str
    control_id: str
    control_name: str
    explanation: str


class AuditState(TypedDict):
    repo_url: str
    semgrep_findings: Annotated[list[Finding], operator.add]
    osv_findings: Annotated[list[Finding], operator.add]
    github_findings: Annotated[list[Finding], operator.add]
    mapped_controls: Annotated[list[MappedControl], operator.add]
    report: str
    error: str | None

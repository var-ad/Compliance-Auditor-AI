import operator
from typing import Annotated, Literal, TypedDict


class Finding(TypedDict):
    tool: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    file_path: str | None
    rule_id: str | None
    finding_type: str | None  # pre-classified type (e.g. by CVE LLM classifier)
    remediation: str | None   # actionable fix description


class MappedControl(TypedDict):
    finding: Finding
    framework: str
    control_id: str
    control_name: str
    explanation: str


class AuditState(TypedDict):
    repo_url: str
    local_path: str | None
    input_source: str | None  # 'github', 'gitlab', 'bitbucket', 'git', 'local', 'zip'
    repo_name: str | None     # display name for the repo
    semgrep_findings: Annotated[list[Finding], operator.add]
    osv_findings: Annotated[list[Finding], operator.add]
    github_findings: Annotated[list[Finding], operator.add]
    secrets_findings: Annotated[list[Finding], operator.add]
    governance_findings: Annotated[list[Finding], operator.add]
    sbom_findings: Annotated[list[Finding], operator.add]
    iac_findings: Annotated[list[Finding], operator.add]
    iac_scan_skipped: bool
    _mapper_run_count: Annotated[int, operator.add]
    cicd_findings: Annotated[list[Finding], operator.add]
    data_classification_findings: Annotated[list[Finding], operator.add]
    mapped_controls: Annotated[list[MappedControl], operator.add]
    report: str
    error: str | None

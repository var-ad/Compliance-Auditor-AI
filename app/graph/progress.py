"""In-memory progress tracker for LangGraph pipeline node execution.

Tracks the status of each node across all audit runs.
Uses asyncio.Event to signal completion to consumers.
"""

import time
from typing import Any

# ---------------------------------------------------------------------------
# Node status constants
# ---------------------------------------------------------------------------

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"

# ---------------------------------------------------------------------------
# All 14 nodes in execution order (logical groups for the UI)
# ---------------------------------------------------------------------------

ALL_NODES: list[str] = [
    "orchestrator",
    "fan_out",
    "semgrep",
    "osv",
    "github",
    "scan_secrets_pii",
    "scan_repo_governance",
    "scan_sbom_license",
    "scan_iac_config",
    "scan_cicd_security",
    "scan_data_classification",
    "scanner_merge",
    "compliance_mapper",
    "report_generator",
]

# Node groups for organization in the UI display
NODE_GROUPS: list[dict[str, Any]] = [
    {"label": "Setup", "nodes": ["orchestrator", "fan_out"]},
    {"label": "Scanning", "nodes": [
        "semgrep", "osv", "github",
        "scan_secrets_pii", "scan_repo_governance",
        "scan_sbom_license", "scan_iac_config",
        "scan_cicd_security", "scan_data_classification",
    ]},
    {"label": "Merge", "nodes": ["scanner_merge"]},
    {"label": "Mapping", "nodes": ["compliance_mapper"]},
    {"label": "Report", "nodes": ["report_generator"]},
]

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

_store: dict[str, dict[str, Any]] = {}
_results: dict[str, Any] = {}


def create_audit(audit_id: str) -> dict[str, Any]:
    """Create a new audit tracker entry for all 14 nodes."""
    entry = {
        "audit_id": audit_id,
        "status": STATUS_RUNNING,
        "created_at": time.time(),
        "completed_at": None,
        "error": None,
        "nodes": {
            name: {
                "name": name,
                "status": STATUS_PENDING,
                "started_at": None,
                "completed_at": None,
                "error": None,
            }
            for name in ALL_NODES
        },
    }
    _store[audit_id] = entry
    return entry


def mark_running(audit_id: str, node_name: str) -> None:
    """Set a node to running status."""
    entry = _store.get(audit_id)
    if entry and node_name in entry["nodes"]:
        entry["nodes"][node_name]["status"] = STATUS_RUNNING
        entry["nodes"][node_name]["started_at"] = time.time()


def mark_completed(audit_id: str, node_name: str) -> None:
    """Set a node to completed status."""
    entry = _store.get(audit_id)
    if entry and node_name in entry["nodes"]:
        entry["nodes"][node_name]["status"] = STATUS_COMPLETED
        entry["nodes"][node_name]["completed_at"] = time.time()


def mark_skipped(audit_id: str, node_name: str) -> None:
    """Set a node to skipped status."""
    entry = _store.get(audit_id)
    if entry and node_name in entry["nodes"]:
        entry["nodes"][node_name]["status"] = STATUS_SKIPPED
        entry["nodes"][node_name]["completed_at"] = time.time()


def mark_error(audit_id: str, node_name: str, error_msg: str) -> None:
    """Set a node to error status."""
    entry = _store.get(audit_id)
    if entry and node_name in entry["nodes"]:
        entry["nodes"][node_name]["status"] = STATUS_ERROR
        entry["nodes"][node_name]["completed_at"] = time.time()
        entry["nodes"][node_name]["error"] = error_msg
        entry["error"] = error_msg


def complete_audit(audit_id: str, error: str | None = None) -> None:
    """Mark the entire audit as complete."""
    entry = _store.get(audit_id)
    if not entry:
        return
    entry["status"] = STATUS_ERROR if error else STATUS_COMPLETED
    entry["completed_at"] = time.time()
    entry["error"] = error


def get_status(audit_id: str) -> dict[str, Any] | None:
    """Get the current tracker entry for an audit run."""
    entry = _store.get(audit_id)
    if not entry:
        return None
    return {
        "audit_id": entry["audit_id"],
        "status": entry["status"],
        "created_at": entry["created_at"],
        "completed_at": entry["completed_at"],
        "error": entry["error"],
        "nodes": list(entry["nodes"].values()),
    }


def save_result(audit_id: str, result: Any) -> None:
    """Store the final audit result."""
    _results[audit_id] = result


def get_result(audit_id: str) -> Any:
    """Retrieve the final audit result."""
    return _results.get(audit_id)


def cleanup(audit_id: str) -> None:
    """Remove an audit from the store."""
    _store.pop(audit_id, None)
    _results.pop(audit_id, None)

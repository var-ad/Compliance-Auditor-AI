import asyncio
import json
import shutil
import tempfile

from app.graph.state import AuditState, Finding


async def run_semgrep(state: AuditState) -> dict:
    temp_dir = tempfile.mkdtemp()
    try:
        await _clone_repo(state["repo_url"], temp_dir)
        process = await asyncio.create_subprocess_exec(
            "semgrep",
            "--config",
            "auto",
            "--json",
            temp_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0 and not stdout:
            raise RuntimeError(stderr.decode(errors="replace"))

        data = json.loads(stdout.decode() or "{}")
        findings: list[Finding] = []
        for result in data.get("results", []):
            extra = result.get("extra", {})
            findings.append(
                {
                    "tool": "semgrep",
                    "severity": extra.get("severity", "medium").lower(),
                    "title": result["check_id"],
                    "description": extra.get("message", ""),
                    "file_path": result.get("path"),
                    "rule_id": result["check_id"],
                }
            )

        return {"semgrep_findings": findings}
    except Exception as exc:
        return {"semgrep_findings": [], "error": str(exc)}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


async def _clone_repo(repo_url: str, destination: str) -> None:
    process = await asyncio.create_subprocess_exec(
        "git",
        "clone",
        "--depth",
        "1",
        repo_url,
        destination,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(stderr.decode(errors="replace"))

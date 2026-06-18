import asyncio
import json
import os
import shutil
import sys

CI = os.environ.get("CI", "").lower() in ("1", "true", "yes")

REQUIRED_TOOLS = ("git", "semgrep", "osv-scanner")


def missing_tools() -> list[str]:
    return [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]


async def main() -> None:
    missing = missing_tools()
    if missing:
        msg = (
            f"Missing required CLI tools: {', '.join(missing)}. "
            "Install them and ensure they are on PATH."
        )
        print(msg)
        if CI:
            sys.exit(1)
        return

    from app.graph.graph import compliance_graph

    initial_state = {
        "repo_url": "https://github.com/fastapi/fastapi",
        "semgrep_findings": [],
        "osv_findings": [],
        "github_findings": [],
        "mapped_controls": [],
        "report": "",
        "error": None,
    }

    result = await compliance_graph.ainvoke(initial_state)
    if result.get("error"):
        print(f"Error: {result['error']}")
        return

    report = json.loads(result["report"])
    print(f"Semgrep findings: {len(result.get('semgrep_findings', []))}")
    print(f"OSV findings: {len(result.get('osv_findings', []))}")
    print(f"GitHub findings: {len(result.get('github_findings', []))}")
    print(f"Mapped controls: {len(result.get('mapped_controls', []))}")
    print(f"Overall score: {report['overall_score']}")
    print(f"Executive summary: {report['executive_summary'][:200]}")


if __name__ == "__main__":
    asyncio.run(main())

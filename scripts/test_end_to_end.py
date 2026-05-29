import asyncio
import json
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def missing_tools() -> list[str]:
    required_tools = ("git", "semgrep", "osv-scanner")
    return [tool for tool in required_tools if shutil.which(tool) is None]


async def main() -> None:
    missing = missing_tools()
    if missing:
        print(f"Missing required CLI tools: {', '.join(missing)}")
        print("Install them and make sure they are available on PATH, then rerun this script.")
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

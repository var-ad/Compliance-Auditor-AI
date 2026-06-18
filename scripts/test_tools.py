import asyncio
import subprocess

import httpx

# Import config so load_dotenv() runs via central module
import app.utils.config  # noqa: F401


def test_semgrep() -> bool:
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def test_osv_scanner() -> bool:
    try:
        result = subprocess.run(
            ["osv-scanner", "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


async def test_github_api() -> bool:
    from app.utils.config import GITHUB_TOKEN

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get("https://api.github.com/rate_limit", headers=headers)
    return response.status_code == 200


async def main() -> None:
    checks = {
        "semgrep": test_semgrep(),
        "osv-scanner": test_osv_scanner(),
        "github-api": await test_github_api(),
    }
    for name, passed in checks.items():
        print(f"{name}: {'PASS' if passed else 'FAIL'}")


if __name__ == "__main__":
    asyncio.run(main())

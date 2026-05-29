from app.graph.state import AuditState


async def orchestrate(state: AuditState) -> dict:
    repo_url = state["repo_url"]
    if not (
        repo_url.startswith("https://github.com")
        or repo_url.startswith("git@github.com")
    ):
        return {"error": "Invalid GitHub repo URL"}
    return {}

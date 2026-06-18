import asyncio
import json
import logging
from functools import lru_cache

from groq import AsyncGroq
from sentence_transformers import SentenceTransformer
from supabase import create_client

from app.graph.state import Finding, MappedControl
from app.utils.config import GROQ_API_KEY, LLM_MODEL, SUPABASE_KEY, SUPABASE_URL
from app.utils.llm import groq_retry, strip_markdown_fences

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_model() -> SentenceTransformer:
    """Lazy-loaded SentenceTransformer singleton.

    Loaded only when first needed (not at import time), preserving ~200MB RAM
    when Supabase is not configured.
    """
    return SentenceTransformer("BAAI/bge-base-en-v1.5")


@lru_cache(maxsize=1)
def _get_supabase():
    """Lazy-loaded Supabase client singleton."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def get_embeddings(texts: list[str]) -> list[list[float]]:
    return _get_model().encode(texts).tolist()


async def batch_embed_and_retrieve(
    descriptions: list[str], framework: str
) -> list[list[dict]]:
    """Embed all descriptions at once, then retrieve top-3 chunks per description."""
    # Check Supabase availability before doing expensive embedding
    supabase = _get_supabase()
    if supabase is None:
        return [[] for _ in descriptions]

    # Batch encode: one model call for ALL descriptions
    embeddings = await asyncio.to_thread(get_embeddings, descriptions)

    async def _query(emb: list[float]) -> list[dict]:
        response = await asyncio.to_thread(
            lambda e=emb: supabase.rpc(
                "match_compliance_chunks",
                {
                    "query_embedding": e,
                    "match_framework": framework,
                    "match_count": 2,
                },
            ).execute()
        )
        return response.data or []

    results = await asyncio.gather(*[_query(emb) for emb in embeddings])
    return results


async def batch_retrieve_chunks(
    findings: list[Finding], framework: str
) -> dict[str, list[dict]]:
    """Batch-retrieve top-3 chunks per unique description for a given framework."""
    # Deduplicate by rule_id
    unique: dict[str, str] = {}
    for f in findings:
        rid = f.get("rule_id") or ""
        if rid not in unique:
            unique[rid] = f.get("description", "")

    rule_ids = list(unique.keys())
    descriptions = [unique[rid] for rid in rule_ids]

    all_chunks = await batch_embed_and_retrieve(descriptions, framework)
    return dict(zip(rule_ids, all_chunks))


RAG_CHUNK_SIZE = 5


async def batch_map_findings_gdpr_dpdp(
    findings: list[Finding],
) -> list[MappedControl]:
    if not findings:
        return []

    client = AsyncGroq(api_key=GROQ_API_KEY)
    all_mapped: list[MappedControl] = []

    # Build a lookup map for findings by rule_id
    findings_by_rule: dict[str, Finding] = {}
    for f in findings:
        rid = f.get("rule_id") or ""
        findings_by_rule[rid] = f

    for framework in ("gdpr", "dpdp"):
        try:
            chunks_by_rule = await batch_retrieve_chunks(findings, framework)

            # Check if Supabase returned any chunks — if all empty, skip
            all_chunks_empty = all(
                not chunks_by_rule.get(f.get("rule_id") or "", [])
                for f in findings
            )
            if all_chunks_empty:
                logger.debug("No %s chunks retrieved — skipping", framework)
                continue

            # Build finding entries
            all_entries: list[dict] = []
            for finding in findings:
                rule_id = finding.get("rule_id") or ""
                chunks = chunks_by_rule.get(rule_id, [])
                all_entries.append(
                    {
                        "rule_id": rule_id,
                        "description": finding.get("description", ""),
                        "retrieved_chunks": [
                            {"id": c["id"], "content": c["content"]} for c in chunks
                        ],
                    }
                )

            if not all_entries:
                continue

            # Chunk into smaller groups for reliable JSON responses
            for i in range(0, len(all_entries), RAG_CHUNK_SIZE):
                chunk = all_entries[i : i + RAG_CHUNK_SIZE]
                try:
                    prompt = (
                        "You are a compliance expert. For each finding below, identify the most "
                        "relevant provision from the retrieved chunks.\n"
                        "Return a JSON array where each item has: "
                        "rule_id, control_id, control_name, explanation (2 sentences).\n"
                        'If no provision is relevant, use "NOT_RELEVANT" as the explanation.\n'
                        f"Findings: {json.dumps(chunk)}"
                    )

                    response = await groq_retry(
                        lambda: client.chat.completions.create(
                            model=LLM_MODEL,
                            messages=[{"role": "user", "content": prompt}],
                        )
                    )
                    content = response.choices[0].message.content or ""
                    content = strip_markdown_fences(content)
                    results = json.loads(content)
                except Exception as exc:
                    logger.debug(
                        "RAG chunk %d/%d failed for %s, per-finding fallback: %s",
                        i // RAG_CHUNK_SIZE + 1,
                        (len(all_entries) + RAG_CHUNK_SIZE - 1) // RAG_CHUNK_SIZE,
                        framework,
                        exc,
                    )
                    results = []
                    for entry in chunk:
                        rid = entry["rule_id"]
                        finding = findings_by_rule.get(rid)
                        if not finding:
                            continue
                        f_results = await _per_finding_fallback(
                            [finding], framework, client
                        )
                        results.extend(f_results)

                for item in results:
                    explanation = item.get("explanation", "") or ""
                    control_id = item.get("control_id", "") or ""

                    # LLM sometimes puts NOT_RELEVANT/NOT_APPLICABLE in
                    # control_id instead of explanation — catch both
                    skip_keywords = ("NOT_RELEVANT", "NOT_APPLICABLE")
                    if any(k in explanation.upper() for k in skip_keywords):
                        continue
                    if any(k in control_id.upper() for k in skip_keywords):
                        continue

                    rule_id = item.get("rule_id", "")
                    finding = findings_by_rule.get(rule_id)
                    if not finding:
                        continue

                    all_mapped.append(
                        {
                            "finding": finding,
                            "framework": framework,
                            "control_id": control_id,
                            "control_name": item.get("control_name", ""),
                            "explanation": explanation,
                        }
                    )

        except Exception as exc:
            logger.debug(
                "Framework %s skipped entirely: %s", framework, exc
            )
            continue

    return all_mapped


async def _per_finding_fallback(
    findings: list[Finding], framework: str, client: AsyncGroq
) -> list[dict]:
    """Fallback: per-finding Groq call when batch JSON parsing fails."""
    results = []
    for finding in findings:
        try:
            chunks = await batch_embed_and_retrieve(
                [finding.get("description", "")], framework
            )
            chunks = chunks[0] if chunks else []
            for chunk in chunks:
                prompt = (
                    "You are a compliance expert.\n"
                    f"Security finding: {finding.get('description', '')}\n"
                    f"Relevant {framework.upper()} provision: {chunk['content']}\n"
                    'If this provision is not directly relevant, respond with: "NOT_RELEVANT"\n'
                    "Explain in 2 sentences why this finding is relevant to this provision.\n"
                    "Be specific. Reference the article/rule number."
                )
                resp = await groq_retry(
                    lambda: client.chat.completions.create(
                        model=LLM_MODEL,
                        messages=[{"role": "user", "content": prompt}],
                    ),
                    max_retries=2,
                )
                explanation = resp.choices[0].message.content or ""
                if "NOT_RELEVANT" in explanation:
                    continue

                metadata = chunk.get("metadata") or {}
                control_id = chunk["id"]
                control_name = chunk["content"].splitlines()[0]
                results.append(
                    {
                        "rule_id": finding.get("rule_id", ""),
                        "control_id": control_id,
                        "control_name": control_name,
                        "explanation": explanation,
                    }
                )
        except Exception as exc:
            logger.debug("Per-finding fallback failed for %s: %s", framework, exc)
            continue
    return results

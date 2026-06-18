import asyncio
import logging
from functools import lru_cache

from groq import AsyncGroq
from sentence_transformers import SentenceTransformer
from supabase import create_client

from app.graph.state import Finding, MappedControl
from app.utils.config import GROQ_API_KEY, LLM_MODEL, SUPABASE_KEY, SUPABASE_URL
from app.utils.llm import groq_retry

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


async def _retrieve_control_text(
    supabase, control_id: str, max_chars: int = 1500
) -> str:
    """Retrieve the full regulation text for a control by its chunk ID.

    e.g. control_id='gdpr_article_32' returns the text of GDPR Art. 32.
    Truncated to max_chars to keep LLM context manageable.
    """
    try:
        response = await asyncio.to_thread(
            lambda: supabase.table("compliance_chunks")
            .select("content")
            .eq("id", control_id)
            .execute()
        )
        data = response.data
        if data and len(data) > 0:
            text = data[0].get("content", "")
            return text[:max_chars] if text else ""
        return ""
    except Exception as exc:
        logger.debug("Failed to retrieve text for %s: %s", control_id, exc)
        return ""


async def enrich_gdpr_dpdp_explanations(
    curated_controls: list[MappedControl],
    findings: list[Finding],
) -> list[MappedControl] | None:
    """Enrich curated GDPR/DPDP controls with explanations grounded in regulation text.

    The curated table has already selected the CORRECT control (Art. 32 / Rule 8).
    This function:
    1. Retrieves the actual regulation text for each unique control from Supabase
    2. Uses LLM to write a specific, technically-grounded explanation
    3. Returns enriched controls (or None if enrichment is not possible)

    Falls back to the original curated explanations if anything fails.
    """
    supabase = _get_supabase()
    if supabase is None:
        return None

    client = AsyncGroq(api_key=GROQ_API_KEY)

    # Retrieve regulation text for each unique (framework, control_id) once
    control_texts: dict[tuple[str, str], str] = {}
    for mc in curated_controls:
        key = (mc.get("framework", ""), mc.get("control_id", ""))
        if key not in control_texts:
            text = await _retrieve_control_text(supabase, key[1])
            control_texts[key] = text

    # If no regulation text was retrieved at all, skip enrichment
    if not any(control_texts.values()):
        return None

    # Build a finding lookup by rule_id for description context
    findings_by_rule: dict[str, Finding] = {}
    for f in findings:
        rid = f.get("rule_id") or ""
        findings_by_rule[rid] = f

    # Enrich each control with a grounded explanation
    enriched: list[MappedControl] = []
    for mc in curated_controls:
        fw = mc.get("framework", "")
        cid = mc.get("control_id", "")
        reg_text = control_texts.get((fw, cid), "")

        if not reg_text:
            enriched.append(mc)  # Keep curated explanation
            continue

        finding = mc.get("finding", {})
        description = finding.get("description", "") or ""
        title = finding.get("title", "") or ""

        if not description and not title:
            enriched.append(mc)
            continue

        try:
            prompt = (
                f"You are a compliance expert. Explain in 2 sentences how this security "
                f"finding relates to the {fw.upper()} provision below.\n\n"
                f"Security finding: {title} — {description}\n\n"
                f"Relevant {fw.upper()} provision ({cid}):\n{reg_text}\n\n"
                f"Write a specific, technically-grounded explanation that references the "
                f"provision text. Be concrete about how the finding violates the requirement."
            )
            resp = await groq_retry(
                lambda: client.chat.completions.create(
                    model=LLM_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                ),
                max_retries=2,
            )
            new_explanation = resp.choices[0].message.content or ""
            if new_explanation:
                mc = dict(mc)  # copy so we don't mutate input
                mc["explanation"] = new_explanation
        except Exception:
            pass  # Keep original curated explanation

        enriched.append(mc)

    return enriched

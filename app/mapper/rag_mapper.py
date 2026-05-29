import asyncio
import os

from dotenv import load_dotenv
from groq import AsyncGroq
from sentence_transformers import SentenceTransformer
from supabase import create_client

from app.graph.state import Finding, MappedControl

MODEL = SentenceTransformer("BAAI/bge-base-en-v1.5")


def get_embedding(text: str) -> list[float]:
    return MODEL.encode(text).tolist()


async def retrieve_relevant_controls(finding: Finding, framework: str) -> list[dict]:
    try:
        load_dotenv()
        supabase_url = os.getenv("SUPABASE_URL")
        supabase_key = os.getenv("SUPABASE_KEY")
        if not supabase_url or not supabase_key:
            return []

        query_embedding = await asyncio.to_thread(get_embedding, finding["description"])

        supabase = create_client(supabase_url, supabase_key)
        response = await asyncio.to_thread(
            lambda: supabase.rpc(
                "match_compliance_chunks",
                {
                    "query_embedding": query_embedding,
                    "match_framework": framework,
                    "match_count": 3,
                },
            ).execute()
        )
        return response.data or []
    except Exception:
        return []


async def map_finding_gdpr_dpdp(finding: Finding) -> list[MappedControl]:
    try:
        mapped_controls: list[MappedControl] = []
        load_dotenv()
        client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))

        for framework in ("gdpr", "dpdp"):
            chunks = await retrieve_relevant_controls(finding, framework)
            for chunk in chunks:
                prompt = (
                    "You are a compliance expert.\n"
                    f"Security finding: {finding['description']}\n"
                    f"Relevant {framework.upper()} provision: {chunk['content']}\n"
                    "If this provision is not directly relevant to the finding, respond with: "
                    '"NOT_RELEVANT"\n'
                    "Explain in 2 sentences why this finding is relevant to this provision.\n"
                    "Be specific. Reference the article/rule number."
                )
                response = await client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[{"role": "user", "content": prompt}],
                )
                explanation = response.choices[0].message.content or ""
                if explanation.strip().upper() == "NOT_RELEVANT":
                    continue

                metadata = chunk.get("metadata") or {}
                mapped_controls.append(
                    {
                        "finding": finding,
                        "framework": metadata.get("framework", chunk.get("framework", framework)),
                        "control_id": chunk["id"],
                        "control_name": chunk["content"].splitlines()[0],
                        "explanation": explanation,
                    }
                )

        return mapped_controls
    except Exception:
        return []

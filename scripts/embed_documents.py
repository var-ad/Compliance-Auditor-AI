import asyncio
import io
import os
import re

import fitz
import httpx
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
from supabase import create_client

GDPR_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32016R0679"
DPDP_URL = "https://www.dpdpa.com/DPDP_Rules_2025_English_only.pdf"
MODEL = SentenceTransformer("BAAI/bge-base-en-v1.5")


async def fetch_bytes(url: str) -> bytes:
    async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.content


async def extract_gdpr_articles(html: bytes) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    article_positions = [
        (index, int(match.group(1)))
        for index, line in enumerate(lines)
        if (match := re.fullmatch(r"Article\s+(\d+)", line))
    ]

    chunks: list[dict] = []
    for position, (line_index, article_number) in enumerate(article_positions):
        if article_number < 1 or article_number > 99:
            continue

        next_index = (
            article_positions[position + 1][0]
            if position + 1 < len(article_positions)
            else len(lines)
        )
        article_lines = lines[line_index:next_index]
        if not article_lines:
            continue

        text = "\n".join(article_lines)
        chunks.append(
            {
                "id": f"gdpr_article_{article_number}",
                "content": text,
                "framework": "gdpr",
                "metadata": {"framework": "gdpr", "article": article_number},
            }
        )

    return chunks


async def extract_dpdp_rules(pdf_bytes: bytes) -> list[dict]:
    document = fitz.open(stream=io.BytesIO(pdf_bytes), filetype="pdf")
    text = "\n".join(page.get_text() for page in document)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    rule_positions = [
        (index, int(match.group(1)))
        for index, line in enumerate(lines)
        if (match := re.match(r"^(\d+)\.\s+", line))
    ]

    chunks: list[dict] = []
    seen_rules: set[int] = set()
    for position, (line_index, rule_number) in enumerate(rule_positions):
        if rule_number in seen_rules:
            continue
        seen_rules.add(rule_number)

        next_index = (
            rule_positions[position + 1][0]
            if position + 1 < len(rule_positions)
            else len(lines)
        )
        rule_lines = lines[line_index:next_index]
        if not rule_lines:
            continue

        text = "\n".join(rule_lines)
        chunks.append(
            {
                "id": f"dpdp_rule_{rule_number}",
                "content": text,
                "framework": "dpdp",
                "metadata": {"framework": "dpdp", "rule": rule_number},
            }
        )

    return chunks


def get_embedding(text: str) -> list[float]:
    return MODEL.encode(text).tolist()


async def embed_text(text: str) -> list[float]:
    return await asyncio.to_thread(get_embedding, text)


async def upsert_chunk(supabase, chunk: dict, embedding: list[float]) -> None:
    payload = {
        "id": chunk["id"],
        "content": chunk["content"],
        "framework": chunk["framework"],
        "metadata": chunk["metadata"],
        "embedding": embedding,
    }
    await asyncio.to_thread(
        lambda: supabase.table("compliance_chunks").upsert(payload).execute()
    )


async def embed_chunks(supabase, chunks: list[dict]) -> None:
    for chunk in chunks:
        embedding = await embed_text(chunk["content"])
        await upsert_chunk(supabase, chunk, embedding)

        metadata = chunk["metadata"]
        if chunk["framework"] == "gdpr":
            print(f"Embedded GDPR article {metadata['article']}")
        else:
            print(f"Embedded DPDP rule {metadata['rule']}")

        await asyncio.sleep(0.5)


async def main() -> None:
    load_dotenv()
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")

    if not supabase_url or not supabase_key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY are required")

    supabase = create_client(supabase_url, supabase_key)

    gdpr_html, dpdp_pdf = await asyncio.gather(fetch_bytes(GDPR_URL), fetch_bytes(DPDP_URL))
    gdpr_chunks = await extract_gdpr_articles(gdpr_html)
    dpdp_chunks = await extract_dpdp_rules(dpdp_pdf)

    await embed_chunks(supabase, gdpr_chunks)
    await embed_chunks(supabase, dpdp_chunks)


if __name__ == "__main__":
    asyncio.run(main())

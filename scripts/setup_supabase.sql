-- Enable pgvector
create extension if not exists vector;

-- Drop and recreate table with 768 dimensions
drop table if exists compliance_chunks;

create table compliance_chunks (
  id text primary key,
  content text not null,
  framework text not null,
  metadata jsonb,
  embedding vector(768)
);

-- Audit result cache table
create table if not exists audit_cache (
  cache_key text primary key,
  report jsonb not null,
  created_at timestamptz default now()
);

-- Index for efficient stale-entry cleanup
create index if not exists idx_audit_cache_created_at on audit_cache (created_at);

-- Create similarity search function
create or replace function match_compliance_chunks(
  query_embedding vector(768),
  match_framework text,
  match_count int default 3
)
returns table (
  id text,
  content text,
  framework text,
  metadata jsonb,
  similarity float
)
language plpgsql
as $$
begin
  return query
  select
    compliance_chunks.id,
    compliance_chunks.content,
    compliance_chunks.framework,
    compliance_chunks.metadata,
    1 - (compliance_chunks.embedding <=> query_embedding) as similarity
  from compliance_chunks
  where compliance_chunks.framework = match_framework
  order by compliance_chunks.embedding <=> query_embedding
  limit match_count;
end;
$$;

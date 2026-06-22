import logging
import os
import re
from typing import Any, TypedDict

from app.data_scan.pii_field_patterns import (
    DIRECT_IDENTIFIERS,
    ENCRYPTION_SIGNALS,
    SENSITIVE_CATEGORIES,
    WEAK_IDENTIFIERS,
)
from app.graph.state import AuditState, Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema file discovery
# ---------------------------------------------------------------------------

_SCHEMA_PATTERNS: list[dict] = [
    # Prisma
    {"glob": "schema.prisma", "parser": "prisma"},
    # SQLAlchemy / Django models (Python)
    {"glob": "models.py", "parser": "python_orm"},
    # TypeORM entities
    {"glob": "*.entity.ts", "parser": "typeorm"},
    {"glob": "*.entity.js", "parser": "typeorm"},
    # Mongoose schemas
    {"glob": "*.schema.ts", "parser": "mongoose"},
    {"glob": "*.schema.js", "parser": "mongoose"},
    # OpenAPI / Swagger
    {"glob": "openapi.yaml", "parser": "openapi"},
    {"glob": "openapi.yml", "parser": "openapi"},
    {"glob": "swagger.yaml", "parser": "openapi"},
    {"glob": "swagger.yml", "parser": "openapi"},
    {"glob": "openapi.json", "parser": "openapi"},
    {"glob": "swagger.json", "parser": "openapi"},
    # GraphQL schemas
    {"glob": "*.graphql", "parser": "graphql"},
    {"glob": "*.gql", "parser": "graphql"},
    # SQL migrations
    {"glob": "*.sql", "parser": "sql_migration"},
]

# Directories to skip
_SKIP_DIRS = {
    "node_modules", ".venv", "venv", ".git", "__pycache__",
    "vendor", "dist", "build", ".next", "target",
}


def _discover_schema_files(repo_path: str) -> list[dict]:
    """Walk repo and find schema definition files by name pattern.

    Returns list of (filepath, parser_name) dicts.
    """
    found: list[dict] = []
    prisma_found = False

    for root, dirs, files in os.walk(repo_path):
        rel = os.path.relpath(root, repo_path).replace("\\", "/")
        parts = rel.split("/")
        if any(p in _SKIP_DIRS for p in parts):
            continue

        for fn in files:
            fpath = os.path.join(root, fn)

            # Try each pattern
            for pat in _SCHEMA_PATTERNS:
                glob = pat["glob"]
                parser = pat["parser"]
                matched = False

                if "*" in glob:
                    # Simple glob: match suffix
                    suffix = glob.lstrip("*")
                    if fn.lower().endswith(suffix.lower()):
                        matched = True
                else:
                    if fn.lower() == glob.lower():
                        matched = True

                if matched:
                    # For Prisma, only match the first schema.prisma
                    if parser == "prisma":
                        if prisma_found:
                            continue
                        prisma_found = True
                    found.append({"path": fpath, "parser": parser})
                    break  # first match wins per file

    return found


# ---------------------------------------------------------------------------
# Parsers — each returns list of ModelInfo objects
# ---------------------------------------------------------------------------

class ParsedField(TypedDict):
    name: str
    field_type: str
    line_number: int
    comment: str


class ParsedModel(TypedDict):
    name: str
    source_file: str
    fields: list[ParsedField]


def _parse_prisma(filepath: str) -> list[ParsedModel]:
    """Parse Prisma schema.prisma for model definitions."""
    models: list[ParsedModel] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return models

    # Extract model blocks
    model_re = re.compile(
        r"model\s+(\w+)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}", re.DOTALL
    )
    for m in model_re.finditer(content):
        model_name = m.group(1)
        body = m.group(2)
        fields = []
        for line in body.strip().split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                field_name = parts[0]
                field_type = parts[1]
                # Remove decorators like @id, @unique, @default(...)
                field_type = re.sub(r"@\w+.*", "", field_type).strip()
                comment = ""
                if "//" in stripped:
                    comment = stripped.split("//", 1)[-1].strip()
                fields.append(ParsedField(
                    name=field_name, field_type=field_type,
                    line_number=0, comment=comment,
                ))
        if fields:
            models.append(ParsedModel(
                name=model_name, source_file=filepath, fields=fields,
            ))
    return models


def _parse_python_orm(filepath: str) -> list[ParsedModel]:
    """Parse Python ORM models (SQLAlchemy or Django)."""
    models: list[ParsedModel] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return models

    current_model: str | None = None
    current_fields: list[ParsedField] = []
    model_re = re.compile(r"^\s*(?:class\s+(\w+).*?\bModel\b|\w+\s*=\s*declarative_base\(\))")

    for lineno, line in enumerate(lines, 1):
        # Detect new model class
        mm = model_re.search(line)
        if mm:
            if current_model and current_fields:
                models.append(ParsedModel(
                    name=current_model, source_file=filepath, fields=current_fields,
                ))
            current_model = mm.group(1) or "Base"
            current_fields = []
            continue

        if current_model is None:
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith('"""'):
            continue

        # SQLAlchemy: field = Column(Type)
        # Django: field = models.TypeField()
        orm_match = re.match(
            r"(\w+)\s*=\s*(?:db\.\w*Column|Column|models\.\w+)"
            r"\s*\(\s*(\w+)",
            stripped,
        )
        if orm_match:
            field_name = orm_match.group(1)
            field_type = orm_match.group(2)
            comment = line.split("#", 1)[-1].strip() if "#" in line else ""
            current_fields.append(ParsedField(
                name=field_name, field_type=field_type,
                line_number=lineno, comment=comment,
            ))

    if current_model and current_fields:
        models.append(ParsedModel(
            name=current_model, source_file=filepath, fields=current_fields,
        ))
    return models


def _parse_typeorm(filepath: str) -> list[ParsedModel]:
    """Parse TypeORM entity files with @Column() decorators."""
    models: list[ParsedModel] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return models

    # Find @Entity() classes
    entity_re = re.compile(
        r"@Entity\([^)]*\)\s*\n\s*(?:export\s+)?(?:class\s+(\w+))",
        re.DOTALL,
    )
    for m in entity_re.finditer(content):
        model_name = m.group(1)
        fields = []
        # Walk lines within the class body
        # (simplified: find @Column decorators followed by field declarations)
        col_re = re.compile(
            r"@Column\([^)]*\)\s*\n\s*(\w+)\s*[:=]\s*(\w+)",
            re.DOTALL,
        )
        for cm in col_re.finditer(content):
            field_name = cm.group(1)
            field_type = cm.group(2)
            fields.append(ParsedField(
                name=field_name, field_type=field_type,
                line_number=0, comment="",
            ))
        if fields:
            models.append(ParsedModel(
                name=model_name, source_file=filepath, fields=fields,
            ))
    return models


def _parse_mongoose(filepath: str) -> list[ParsedModel]:
    """Parse Mongoose schema definitions."""
    models: list[ParsedModel] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return models

    # Find new Schema({...}) definitions
    schema_re = re.compile(
        r"(?:const|let|var)\s+(\w+)\s*=\s*new\s+Schema\(\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}\s*[,)]",
        re.DOTALL,
    )
    for m in schema_re.finditer(content):
        model_name = m.group(1)
        body = m.group(2)
        fields = []
        for line in body.strip().split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            # Match field_name: { type: Type, ... } or field_name: Type
            fm = re.match(r"(\w+)\s*:\s*(\{.*?\}|[^,}]+)", stripped)
            if fm:
                fields.append(ParsedField(
                    name=fm.group(1), field_type="object",
                    line_number=0, comment="",
                ))
        if fields:
            models.append(ParsedModel(
                name=model_name + "Schema", source_file=filepath, fields=fields,
            ))
    return models


def _parse_openapi(filepath: str) -> list[ParsedModel]:
    """Parse OpenAPI/Swagger spec for schema definitions."""
    models: list[ParsedModel] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return models

    # Handle JSON and YAML — look for "components.schemas.*" or "definitions.*"
    # Simple regex-based extraction (full YAML parse is overkill here)
    schema_section = re.search(
        r"(?:schemas|definitions)\s*:\s*\n((?:\s+\w+.*\n)+)",
        content,
    )
    if not schema_section:
        return models

    # Extract individual model names
    model_names = re.findall(r"^\s+(\w+)\s*:\s*\n", schema_section.group(1), re.MULTILINE)
    for _model_name in model_names:
        fields = []
        # Extract property names within each model
        # (This is a simplification — a full YAML parser would be better)
        models.append(ParsedModel(
            name=_model_name, source_file=filepath, fields=fields,
        ))
    return models


def _parse_graphql(filepath: str) -> list[ParsedModel]:
    """Parse GraphQL schema files for type definitions."""
    models: list[ParsedModel] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return models

    # Extract type/interface definitions
    type_re = re.compile(r"(?:type|interface)\s+(\w+)\s*\{([^}]+)\}", re.DOTALL)
    for m in type_re.finditer(content):
        model_name = m.group(1)
        body = m.group(2)
        fields = []
        for line in body.strip().split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if parts and not parts[0].startswith(("_", "@")):
                field_name = parts[0]
                comment = line.split("#", 1)[-1].strip() if "#" in line else ""
                fields.append(ParsedField(
                    name=field_name, field_type=parts[1] if len(parts) > 1 else "",
                    line_number=0, comment=comment,
                ))
        if fields:
            models.append(ParsedModel(
                name=model_name, source_file=filepath, fields=fields,
            ))
    return models


def _parse_sql_migration(filepath: str) -> list[ParsedModel]:
    """Parse SQL migration files for CREATE TABLE statements."""
    models: list[ParsedModel] = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return models

    # Find CREATE TABLE tablename ( ... );
    table_re = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:\w+\.)?(\w+)\s*\(([^;]+)\)",
        re.IGNORECASE | re.DOTALL,
    )
    for m in table_re.finditer(content):
        table_name = m.group(1)
        body = m.group(2)
        fields = []
        for line in body.strip().split("\n"):
            stripped = line.strip().rstrip(",")
            if not stripped or stripped.startswith("--") or stripped.startswith("/*"):
                continue
            # Skip constraints and indexes
            if any(stripped.upper().startswith(kw) for kw in
                   ("PRIMARY", "FOREIGN", "INDEX", "KEY", "CONSTRAINT", "UNIQUE", "CHECK")):
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                field_name = parts[0].strip('"`[]"')
                field_type = parts[1]
                comment = line.split("--", 1)[-1].strip() if "--" in line else ""
                fields.append(ParsedField(
                    name=field_name, field_type=field_type,
                    line_number=0, comment=comment,
                ))
        if fields:
            models.append(ParsedModel(
                name=table_name, source_file=filepath, fields=fields,
            ))
    return models


PARSER_MAP = {
    "prisma": _parse_prisma,
    "python_orm": _parse_python_orm,
    "typeorm": _parse_typeorm,
    "mongoose": _parse_mongoose,
    "openapi": _parse_openapi,
    "graphql": _parse_graphql,
    "sql_migration": _parse_sql_migration,
}


# ---------------------------------------------------------------------------
# PII classification
# ---------------------------------------------------------------------------

def _field_matches(field_name: str, keywords: list[str]) -> bool:
    """Check if field_name matches any keyword using word-boundary logic.

    Handles snake_case: matches if any underscore-delimited segment
    is an exact match for the keyword. Also checks exact field name match.
    Does NOT do bare substring matching — prevents 'email' matching
    'expiryReportEmailSentAt'.
    """
    name = field_name.lower().strip()
    # Exact match first
    if name in keywords:
        return True
    # Underscore-delimited word match
    words = name.split("_")
    for keyword in keywords:
        if keyword in words:
            return True
    return False


def _check_model_for_pii(model: ParsedModel) -> tuple[bool, bool, bool]:
    """Check a parsed model for PII patterns.

    Returns (has_direct_pii, has_sensitive_category, has_encryption).
    """
    has_direct = False
    has_sensitive = False
    has_encryption = False
    weak_count = 0

    for field in model["fields"]:
        name_lower = field["name"].lower()
        ftype_lower = field["field_type"].lower()

        # Check encryption signals
        if _has_encryption_signal(name_lower, ftype_lower, field["comment"]):
            has_encryption = True

        # Check sensitive categories first (these are always flagged)
        for cat in SENSITIVE_CATEGORIES:
            if _field_matches(name_lower, [cat["keyword"]]):
                has_sensitive = True
                break

        # Check direct identifiers (word-boundary matching — no false positives
        # on substrings like 'email' in 'expiryReportEmailSentAt')
        if _field_matches(name_lower, DIRECT_IDENTIFIERS):
            if name_lower in WEAK_IDENTIFIERS:
                weak_count += 1
            else:
                has_direct = True

    # Weak identifiers count only if another PII field exists
    if weak_count > 0 and (has_direct or has_sensitive):
        has_direct = True

    return has_direct, has_sensitive, has_encryption


def _has_encryption_signal(
    field_name: str, field_type: str, comment: str
) -> bool:
    """Check if a field name, type, or comment suggests encryption."""
    combined = f"{field_name} {field_type} {comment}".lower()
    return any(sig in combined for sig in ENCRYPTION_SIGNALS)


def _severity_for_identifier(field_name: str) -> str:
    """Determine severity for a PII-unencrypted finding.

    Identity document numbers are high; contact info is medium.
    """
    name_lower = field_name.lower()
    id_keywords = ["ssn", "aadhaar", "aadhar", "pan", "passport", "driving_license",
                    "national_id", "voter_id"]
    if _field_matches(name_lower, id_keywords):
        return "high"
    return "medium"


# ---------------------------------------------------------------------------
# NODE ENTRY POINT
# ---------------------------------------------------------------------------

async def run_scan_data_classification(state: AuditState) -> dict:
    """LangGraph node: detect PII field exposure in schema definitions.

    Finds ORM models, API schemas, and SQL migrations. Classifies field
    names against PII patterns and checks for encryption signals.
    Gracefully no-ops on repos with no detectable schema files.
    """
    if state.get("error"):
        return {}

    repo_path = state.get("local_path")
    if not repo_path:
        return {"data_classification_findings": []}

    schema_files = _discover_schema_files(repo_path)
    if not schema_files:
        logger.info("Data classification: no schema files found — skipping")
        return {"data_classification_findings": []}

    logger.info("Data classification: found %d schema files", len(schema_files))

    findings: list[Finding] = []
    seen_models: set[str] = set()

    for sf in schema_files:
        parser_fn = PARSER_MAP.get(sf["parser"])
        if not parser_fn:
            continue

        models = parser_fn(sf["path"])
        rel_path = os.path.relpath(sf["path"], repo_path).replace("\\", "/")

        for model in models:
            model_key = f"{model['name']}:{rel_path}"
            if model_key in seen_models:
                continue
            seen_models.add(model_key)

            has_direct, has_sensitive, has_encryption = _check_model_for_pii(model)

            # List PII field names for the finding description
            pii_fields = []
            for field in model["fields"]:
                fn_lower = field["name"].lower()
                if _field_matches(fn_lower, DIRECT_IDENTIFIERS):
                    if fn_lower not in WEAK_IDENTIFIERS or has_direct or has_sensitive:
                        pii_fields.append(field["name"])
                elif _field_matches(fn_lower, [cat["keyword"] for cat in SENSITIVE_CATEGORIES]):
                    if fn_lower not in WEAK_IDENTIFIERS or has_direct or has_sensitive:
                        pii_fields.append(field["name"])

            pii_set = sorted(set(pii_fields))
            if not pii_set:
                continue

            # Sensitive category data (regardless of encryption)
            if has_sensitive:
                findings.append({
                    "tool": "data_classification",
                    "severity": "high",
                    "title": f"Sensitive category data: {model['name']}",
                    "description": (
                        f"Model '{model['name']}' in {rel_path} contains "
                        f"special-category data fields: {', '.join(pii_set)}. "
                        f"GDPR Art. 9 / DPDP Rule 4 require additional "
                        f"safeguards for this data even if encrypted."
                    ),
                    "file_path": rel_path,
                    "rule_id": f"dc_sensitive_{model['name'].lower()}",
                    "finding_type": "sensitive_category_data_detected",
                })

            # Unencrypted PII (only if no encryption signal)
            if has_direct and not has_encryption:
                severity = "medium"
                # Escalate if any identity-document fields are present
                for pii in pii_set:
                    if _severity_for_identifier(pii) == "high":
                        severity = "high"
                        break

                findings.append({
                    "tool": "data_classification",
                    "severity": severity,
                    "title": f"Unencrypted PII fields: {model['name']}",
                    "description": (
                        f"Model '{model['name']}' in {rel_path} has PII field(s) "
                        f"({', '.join(pii_set)}) with no detected encryption signal. "
                        f"Consider column-level encryption for these fields."
                    ),
                    "file_path": rel_path,
                    "rule_id": f"dc_unencrypted_{model['name'].lower()}",
                    "finding_type": "pii_field_unencrypted",
                })

    logger.info("Data classification: %d findings from %d models",
                 len(findings), len(seen_models))
    return {"data_classification_findings": findings}

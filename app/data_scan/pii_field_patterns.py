"""PII field name patterns for data classification scanning.

This file is the single configurable source of truth for PII field detection.
Extend these lists as needed — the scanner uses word-boundary matching
on field names (underscore-delimited or exact match), not substring matching.
"""

# ---------------------------------------------------------------------------
# Direct identifiers — fields that likely contain personally identifiable info.
# A model containing 1+ of these fields is flagged as
# "pii_field_unencrypted" if no encryption signal is detected.
#
# false_positive_note: "email" in a contact form model is PII. "email" in a
# config/email_service model is still PII (it's an email address). "phone" as
# a field name is almost always PII. "address" could be a street address or an
# IP address — we flag the field name and let the reviewer decide.
# ---------------------------------------------------------------------------

DIRECT_IDENTIFIERS: list[str] = [
    # Contact / identity
    "email",
    "phone",
    "phone_number",
    "mobile",
    "mobile_number",
    "telephone",
    "whatsapp",
    # Government ID numbers
    "ssn",
    "social_security",
    "aadhaar",
    "aadhar",
    "pan_number",
    "pan",
    "passport",
    "passport_number",
    "driving_license",
    "license_number",
    "voter_id",
    "national_id",
    "uid",
    # Personal details
    "dob",
    "date_of_birth",
    "birth_date",
    "address",
    "full_name",
    "first_name",     # weaker alone — flagged for context
    "last_name",      # weaker alone — flagged for context
    "middle_name",    # weaker alone — flagged for context
    "mother_name",
    "father_name",
    "spouse_name",
    "maiden_name",
    "emergency_contact",
    # Financial
    "bank_account",
    "account_number",
    "credit_card",
    "card_number",
    "cvv",
    "ifsc",
    "routing_number",
    "swift",
    "iban",
]

# Fields that are weak signals alone — only flagged if another PII field
# exists in the same model/table. Prevents false positives on things like
# "first_name" in a game leaderboard model.
WEAK_IDENTIFIERS: set[str] = {
    "first_name", "last_name", "middle_name",
}

# ---------------------------------------------------------------------------
# Special category data — GDPR Art. 9 / DPDP Rule 4 classifications.
# These are flagged regardless of encryption status because they're
# inherently higher-risk under data protection law.
# ---------------------------------------------------------------------------

SENSITIVE_CATEGORIES: list[dict] = [
    {"keyword": "health", "label": "Health data",
     "description": "Health or medical information (GDPR Art. 9(a))"},
    {"keyword": "medical", "label": "Medical data",
     "description": "Medical records or health information"},
    {"keyword": "diagnosis", "label": "Medical diagnosis",
     "description": "Medical diagnosis or treatment information"},
    {"keyword": "biometric", "label": "Biometric data",
     "description": "Biometric data used for identification (GDPR Art. 9(d))"},
    {"keyword": "fingerprint", "label": "Fingerprint data",
     "description": "Fingerprint template or image"},
    {"keyword": "genetic", "label": "Genetic data",
     "description": "Genetic or genomic data (GDPR Art. 9(c))"},
    {"keyword": "dna", "label": "DNA data",
     "description": "DNA sequencing or profile data"},
    {"keyword": "religion", "label": "Religious affiliation",
     "description": "Religious or philosophical beliefs (GDPR Art. 9(b))"},
    {"keyword": "caste", "label": "Caste data",
     "description": "Caste affiliation (sensitive under Indian law)"},
    {"keyword": "sexual_orientation", "label": "Sexual orientation",
     "description": "Sexual orientation data (GDPR Art. 9(e))"},
    {"keyword": "sexual_orientation", "label": "Sexual orientation",
     "description": "Sexual orientation data"},
    {"keyword": "political", "label": "Political opinion",
     "description": "Political opinions or party affiliation (GDPR Art. 9(e))"},
    {"keyword": "union", "label": "Trade union membership",
     "description": "Trade union membership (GDPR Art. 9(f))"},
    {"keyword": "criminal", "label": "Criminal record",
     "description": "Criminal conviction or record data"},
    {"keyword": "password", "label": "Password / credential",
     "description": "Password or authentication credential (also caught by secrets scanner)"},

    # Combined / catch-all patterns
    {"keyword": "sensitive_", "label": "Sensitive data field",
     "description": "Field marked as sensitive"},
    {"keyword": "protected_", "label": "Protected data field",
     "description": "Field marked as protected"},
]


# ---------------------------------------------------------------------------
# Encryption signal patterns
# Look for these in field type names, decorators, comments, and annotations.
# ---------------------------------------------------------------------------

ENCRYPTION_SIGNALS: list[str] = [
    "encrypted",
    "encrypt",
    "cipher",
    "crypto",
    "hashed",
    "hash",
    "bcrypt",
    "argon2",
    "scrypt",
    "pbkdf2",
    "secretbox",
    "aes",
    "aead",
]

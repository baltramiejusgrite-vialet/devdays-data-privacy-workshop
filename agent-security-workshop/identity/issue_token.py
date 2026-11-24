"""Issues the agent's gateway token. Run with: docker compose --profile setup run --rm identity-issuer

Stores only the token's SHA-256 hash in the database, bound to one actor and company,
and writes the token itself to the agent's read-only identity volume. Never prints it.
Re-running replaces the actor's previous token.
"""

import json
import os
import secrets
from pathlib import Path

import psycopg

ACTOR = os.environ.get("TOKEN_ACTOR", "workshop-agent")
COMPANY_ID = int(os.environ.get("TOKEN_COMPANY_ID", "1"))
TOKEN_FILE = Path("/run/identity/access.json")

token = secrets.token_urlsafe(32)
with psycopg.connect(os.environ["ADMIN_DATABASE_URL"]) as db:
    db.execute("DELETE FROM lab_private.access_tokens WHERE actor = %s", (ACTOR,))
    db.execute(
        "INSERT INTO lab_private.access_tokens (token_sha256, actor, company_id, expires_at) "
        "VALUES (sha256(convert_to(%s, 'UTF8')), %s, %s, now() + interval '30 days')",
        (token, ACTOR, COMPANY_ID),
    )

TOKEN_FILE.unlink(missing_ok=True)
TOKEN_FILE.write_text(json.dumps({"gateway_token": token}))
TOKEN_FILE.chmod(0o400)
print(f"Issued a gateway token for actor {ACTOR}, company {COMPANY_ID}, valid 30 days.")

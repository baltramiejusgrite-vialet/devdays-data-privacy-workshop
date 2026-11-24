"""Issues the agent's local model-proxy token. Run with:
    docker compose --profile setup run --rm model-proxy-token-issuer

Writes only the token's SHA-256 hash to the proxy's state volume and the token itself to
the client volume the agent mounts read-only. The OpenAI key is not involved. Re-running
replaces the token; the request budget is kept. Never prints the token.
"""

import hashlib
import json
import secrets
from pathlib import Path

STATE_DIR = Path("/var/lib/model-proxy")
CLIENT_FILE = Path("/run/model-proxy-client/token.json")

token = "mpx_" + secrets.token_urlsafe(32)
(STATE_DIR / "client_token.sha256").write_text(hashlib.sha256(token.encode()).hexdigest())
CLIENT_FILE.unlink(missing_ok=True)
CLIENT_FILE.write_text(json.dumps({"proxy_token": token}))
CLIENT_FILE.chmod(0o444)
print("Issued a new local model-proxy token for the agent.")

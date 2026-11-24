# Manual step 7 tries, from inside the agent container. The token is never printed.
#   1. Call the API without an authentication token.
#   2. Take the agent's real token, change one symbol, and call again.
#   3. For comparison, call with the unchanged token.
# Run from agent-security-workshop:  .\try-auth.ps1
Set-Location $PSScriptRoot
@'
import json, os
from urllib.request import Request, urlopen
from urllib.error import HTTPError

base = os.environ["GATEWAY_URL"]
path = "/companies/1/salary-summary"

def call(label, token):
    headers = {"Authorization": "Bearer " + token} if token is not None else {}
    try:
        with urlopen(Request(base + path, headers=headers), timeout=5) as r:
            status, body = r.status, json.load(r)
    except HTTPError as err:
        status, body = err.code, json.load(err)
    print(f"{label:<38} -> HTTP {status}  {json.dumps(body)}")

token = json.loads(open("/run/identity/access.json").read())["gateway_token"]
position = len(token) // 2
replacement = "A" if token[position] != "A" else "B"
tampered = token[:position] + replacement + token[position + 1:]

print(f"Request: GET {path}")
print(f"Token: {len(token)} characters (not shown). Tampered copy changes 1 character at position {position + 1}.")
print()
call("1. no token", None)
call("2. token with one symbol changed", tampered)
call("3. unchanged token (for comparison)", token)
'@ -replace "`r", '' | docker compose exec -T agent python -

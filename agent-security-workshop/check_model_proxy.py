"""Checks the running model broker from inside the agent, without spending model tokens.

Usage: docker compose exec agent python check_model_proxy.py

Every probe below is rejected by the broker before it contacts OpenAI, so none of them
uses the request budget; the script confirms that by reading the counter before and after.
No token or key is printed.
"""

import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = os.environ.get("OPENAI_BASE_URL", "http://model-proxy:8080/v1").removesuffix("/v1")
TOKEN = json.loads(Path("/run/model-proxy/token.json").read_text())["proxy_token"]
failures = []


def call(method, path, body=None, token=TOKEN, extra_headers=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", **(extra_headers or {})}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    try:
        with urlopen(Request(BASE + path, data=data, headers=headers, method=method), timeout=10) as r:
            return r.status, json.load(r)
    except HTTPError as err:
        return err.code, json.load(err)


def check(label, ok):
    print(f"{'PASS' if ok else 'FAIL'}: {label}", flush=True)
    if not ok:
        failures.append(label)


# Credential separation
env_names = set(os.environ)
check("agent environment has no OPENAI_API_KEY", "OPENAI_API_KEY" not in env_names)
check("no OpenAI key value anywhere in the agent environment",
      not any(v.startswith(("sk-", "sk_")) for v in os.environ.values()))
check("agent's proxy token is a local token, not an OpenAI key", TOKEN.startswith("mpx_"))
check("broker state volume is not mounted in the agent", not Path("/var/lib/model-proxy").exists())

# Fixed endpoint, model and limits, read from the broker
status, info = call("GET", "/usage")
check("broker reports its policy to an authenticated client", status == 200)
model = info.get("model")
check(f"fixed endpoint is POST /v1/responses ({info.get('endpoint')})", info.get("endpoint") == "POST /v1/responses")
check(f"fixed model is {model}", bool(model))
check(f"output cap is 4096 tokens ({info.get('max_output_tokens')})", info.get("max_output_tokens") == 4096)
check(f"request budget is 60 ({info.get('requests_used')} used, persisted by the broker)",
      info.get("request_limit") == 60 and isinstance(info.get("requests_used"), int))
used_before = info.get("requests_used")

valid = {"model": model, "input": "probe", "max_output_tokens": 16}
probes = [
    ("missing authentication is rejected", "POST", "/v1/responses", valid, None, 401),
    ("wrong proxy token is rejected", "POST", "/v1/responses", valid, "mpx_wrong", 401),
    ("the real OpenAI key format is not accepted as a proxy token", "POST", "/v1/responses", valid, "sk-test", 401),
    ("usage endpoint needs authentication", "GET", "/usage", None, None, 401),
    ("another model is rejected", "POST", "/v1/responses", {**valid, "model": "gpt-4o"}, TOKEN, 400),
    ("missing model is rejected", "POST", "/v1/responses", {"input": "probe"}, TOKEN, 400),
    ("another endpoint (/v1/chat/completions) is rejected", "POST", "/v1/chat/completions", valid, TOKEN, 403),
    ("another endpoint (/v1/embeddings) is rejected", "POST", "/v1/embeddings", valid, TOKEN, 403),
    ("listing models is rejected", "GET", "/v1/models", None, TOKEN, 403),
    ("hosted tool web_search is rejected", "POST", "/v1/responses",
     {**valid, "tools": [{"type": "web_search"}]}, TOKEN, 400),
    ("hosted tool code_interpreter is rejected", "POST", "/v1/responses",
     {**valid, "tools": [{"type": "code_interpreter", "container": {"type": "auto"}}]}, TOKEN, 400),
    ("output limit above 4096 is rejected", "POST", "/v1/responses", {**valid, "max_output_tokens": 4097}, TOKEN, 400),
    ("malformed output limit (text) is rejected", "POST", "/v1/responses",
     {**valid, "max_output_tokens": "4096"}, TOKEN, 400),
    ("malformed output limit (zero) is rejected", "POST", "/v1/responses", {**valid, "max_output_tokens": 0}, TOKEN, 400),
    ("malformed output limit (true) is rejected", "POST", "/v1/responses", {**valid, "max_output_tokens": True}, TOKEN, 400),
    ("background request is rejected", "POST", "/v1/responses", {**valid, "background": True}, TOKEN, 400),
]
for label, method, path, body, token, expected in probes:
    status, _ = call(method, path, body, token)
    check(f"{label} (HTTP {status})", status == expected)

status, info = call("GET", "/usage")
check(f"rejected probes used no budget ({used_before} -> {info.get('requests_used')})",
      info.get("requests_used") == used_before)

if failures:
    sys.exit(f"FAIL: {len(failures)} model broker check(s) failed")
print("PASS: model broker enforces credentials, endpoint, model and limits")

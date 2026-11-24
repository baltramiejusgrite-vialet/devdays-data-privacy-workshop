"""Student agent-security entry point: hands the task to the Codex CLI."""

import json
import os
import sys
from pathlib import Path

CREDENTIAL_FILE = Path("/run/credentials/codex/auth.json")
PROXY_TOKEN_FILE = Path("/run/model-proxy/token.json")
MODEL_PROXY_URL = os.environ.get("OPENAI_BASE_URL", "http://model-proxy:8080/v1")
MODEL = os.environ.get("CODEX_MODEL", "gpt-6.2-sol")

CODEX_COMMAND = [
    "codex",
    "exec",
    "--skip-git-repo-check",
    "--cd",
    "/workspace",
    # Codex's own bwrap sandbox cannot start inside Docker; the container is the boundary.
    "--sandbox",
    "danger-full-access",
    # All model traffic goes to the model broker, which checks the local proxy token,
    # enforces the model and limits, and adds the real OpenAI key itself.
    "-c", f"model={MODEL}",
    "-c", "model_provider=proxy",
    "-c", "model_providers.proxy.name=model-proxy",
    "-c", f"model_providers.proxy.base_url={MODEL_PROXY_URL}",
    "-c", "model_providers.proxy.wire_api=responses",
    "-c", "model_providers.proxy.env_key=MODEL_PROXY_TOKEN",
    "-c", "model_providers.proxy.requires_openai_auth=false",
]


def link_credentials():
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    codex_home.mkdir(parents=True, exist_ok=True)
    auth = codex_home / "auth.json"
    if CREDENTIAL_FILE.exists() and not auth.exists():
        auth.symlink_to(CREDENTIAL_FILE)


def load_proxy_token():
    # The local model-proxy token, not an OpenAI key; passed to Codex as MODEL_PROXY_TOKEN.
    os.environ["MODEL_PROXY_TOKEN"] = json.loads(PROXY_TOKEN_FILE.read_text())["proxy_token"]


def close_stdin():
    # codex exec reads extra input from a non-terminal stdin; the task is passed as an argument only.
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: python starter.py "<task for the agent>"')
    link_credentials()
    load_proxy_token()
    close_stdin()
    task = " ".join(sys.argv[1:])
    os.execvp(CODEX_COMMAND[0], CODEX_COMMAND + [task])


if __name__ == "__main__":
    main()

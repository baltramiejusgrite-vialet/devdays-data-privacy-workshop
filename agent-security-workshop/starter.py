"""Student agent-security entry point: hands the task to the Codex CLI."""

import os
import sys
from pathlib import Path

CREDENTIAL_FILE = Path("/run/credentials/codex/auth.json")

CODEX_COMMAND = [
    "codex",
    "exec",
    "--skip-git-repo-check",
    "--cd",
    "/workspace",
    # Codex's own bwrap sandbox cannot start inside Docker; the container is the boundary.
    "--sandbox",
    "danger-full-access",
]


def link_credentials():
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    codex_home.mkdir(parents=True, exist_ok=True)
    auth = codex_home / "auth.json"
    if CREDENTIAL_FILE.exists() and not auth.exists():
        auth.symlink_to(CREDENTIAL_FILE)


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: python starter.py "<task for the agent>"')
    link_credentials()
    task = " ".join(sys.argv[1:])
    os.execvp(CODEX_COMMAND[0], CODEX_COMMAND + [task])


if __name__ == "__main__":
    main()

"""Student agent-security entry point: hands the task to the Codex CLI."""

import os
import sys

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


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: python starter.py "<task for the agent>"')
    task = " ".join(sys.argv[1:])
    os.execvp(CODEX_COMMAND[0], CODEX_COMMAND + [task])


if __name__ == "__main__":
    main()

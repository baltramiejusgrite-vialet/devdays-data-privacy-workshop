"""Starts the lab and runs every repeatable security test (step 8, part 1).

Usage, from agent-security-workshop:  python3 check_security.py   (on Windows: python check_security.py)
Extra pytest arguments are passed through, e.g.  python check_security.py -k audit

Live model tests are skipped unless you add:  -m live_model
The model proxy needs OPENAI_API_KEY in the environment (on Windows it is also read
from your user environment variables). The key is never printed.
"""

import os
import subprocess
import sys
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent


def openai_key_env():
    env = dict(os.environ)
    if not env.get("OPENAI_API_KEY") and sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                env["OPENAI_API_KEY"] = winreg.QueryValueEx(key, "OPENAI_API_KEY")[0]
        except OSError:
            pass
    if not env.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY is not set; the model proxy cannot start.")
    return env


def step(title, command, env=None):
    print(f"\n== {title}", flush=True)
    return subprocess.run(command, cwd=LAB_DIR, env=env, stdin=subprocess.DEVNULL).returncode


def main(extra_args):
    env = openai_key_env()
    if step("Starting services", ["docker", "compose", "up", "-d", "--build", "--wait"], env):
        sys.exit("Services did not start; see docker compose logs.")
    marker = [] if any(a.startswith("-m") for a in extra_args) else ["-m", "not live_model"]
    code = step("Running security tests", [sys.executable, "-m", "pytest", "tests", "-p", "no:cacheprovider",
                                          "-q", *marker, *extra_args])
    print("\nRESULT: all security tests passed" if code == 0 else "\nRESULT: security tests FAILED", flush=True)
    sys.exit(code)


if __name__ == "__main__":
    main(sys.argv[1:])

"""Step 9 checks against the running lab (no model tokens spent). Safe to run repeatedly.

Confirms the real OpenAI key is only in model-proxy and nowhere the agent can read, that the
agent holds only a local proxy token, that the request budget survives a broker restart,
and that check_model_proxy.py passes. The key value is never printed.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
SERVICES = ["agent", "gateway", "model-proxy", "db"]


def run(*args, check=True, timeout=120):
    return subprocess.run(args, cwd=LAB_DIR, capture_output=True, text=True, check=check,
                          stdin=subprocess.DEVNULL, timeout=timeout)


def real_key():
    key = os.environ.get("OPENAI_API_KEY")
    if not key and sys.platform == "win32":
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as reg:
            key = winreg.QueryValueEx(reg, "OPENAI_API_KEY")[0]
    if not key:
        pytest.skip("OPENAI_API_KEY not available on the host to compare against")
    return key


def inspect(service):
    container_id = run("docker", "compose", "ps", "-q", service).stdout.strip()
    if not container_id:
        pytest.skip(f"{service} is not running")
    return json.loads(run("docker", "inspect", container_id).stdout)[0]


def agent_usage():
    code = (
        "import json, urllib.request as u\n"
        "t = json.load(open('/run/model-proxy/token.json'))['proxy_token']\n"
        "r = u.urlopen(u.Request('http://model-proxy:8080/usage', headers={'Authorization': 'Bearer ' + t}), timeout=10)\n"
        "print(json.load(r)['requests_used'])"
    )
    return int(run("docker", "compose", "exec", "-T", "agent", "python", "-c", code).stdout.strip())


# The OpenAI key: only in model-proxy


@pytest.mark.parametrize("service", SERVICES)
def test_key_variable_only_in_model_proxy(service):
    names = {item.split("=", 1)[0] for item in inspect(service)["Config"]["Env"]}
    assert ("OPENAI_API_KEY" in names) is (service == "model-proxy")


@pytest.mark.parametrize("service", ["agent", "gateway", "db"])
def test_key_value_not_in_other_container_config(service):
    assert real_key() not in json.dumps(inspect(service))


def test_model_proxy_holds_the_real_key():
    key = real_key()
    env = dict(item.split("=", 1) for item in inspect("model-proxy")["Config"]["Env"])
    assert env.get("OPENAI_API_KEY") == key


def test_key_not_readable_anywhere_in_agent():
    # Scan everything the agent user can read outside the image's system dirs: env, mounts and scratch space.
    code = (
        "import os, sys\n"
        "needle = sys.stdin.read().strip().encode()\n"
        "hits = [k for k, v in os.environ.items() if needle in v.encode()]\n"
        "for root in ('/workspace', '/run', '/tmp', '/home/agent'):\n"
        "    for d, _, files in os.walk(root):\n"
        "        for f in files:\n"
        "            p = os.path.join(d, f)\n"
        "            try:\n"
        "                if needle in open(p, 'rb').read(): hits.append(p)\n"
        "            except OSError: pass\n"
        "print(len(hits))"
    )
    result = subprocess.run(["docker", "compose", "exec", "-T", "agent", "python", "-c", code], cwd=LAB_DIR,
                            input=real_key(), capture_output=True, text=True, check=True, timeout=120)
    assert result.stdout.strip() == "0"


def test_agent_process_environment_has_no_key():
    code = "import os; print('OPENAI_API_KEY' in os.environ, any(v.startswith('sk-') for v in os.environ.values()))"
    assert run("docker", "compose", "exec", "-T", "agent", "python", "-c", code).stdout.strip() == "False False"


def test_agent_cannot_read_model_proxy_process():
    code = (
        "import os\n"
        "readable = []\n"
        "for pid in filter(str.isdigit, os.listdir('/proc')):\n"
        "    try:\n"
        "        if b'OPENAI_API_KEY' in open(f'/proc/{pid}/environ', 'rb').read(): readable.append(pid)\n"
        "    except OSError: pass\n"
        "print(readable)"
    )
    assert run("docker", "compose", "exec", "-T", "agent", "python", "-c", code).stdout.strip() == "[]"


# The agent's own credential: a local proxy token, read-only


def test_agent_mounts_proxy_token_read_only_and_not_broker_state():
    mounts = {m["Destination"]: m for m in inspect("agent")["Mounts"]}
    assert mounts["/run/model-proxy"]["RW"] is False
    assert "/var/lib/model-proxy" not in mounts
    broker_state = [m for m in mounts.values() if m.get("Name", "").endswith("model_proxy_state")]
    assert broker_state == []


def test_agent_token_is_local_and_not_the_key():
    code = "import json; t = json.load(open('/run/model-proxy/token.json'))['proxy_token']; print(t.startswith('mpx_'), len(t) > 30)"
    assert run("docker", "compose", "exec", "-T", "agent", "python", "-c", code).stdout.strip() == "True True"


def test_broker_stores_only_token_hash():
    code = "import os; print(sorted(os.listdir('/var/lib/model-proxy')))"
    files = run("docker", "compose", "exec", "-T", "model-proxy", "python", "-c", code).stdout.strip()
    assert "client_token.sha256" in files and "token.json" not in files


def test_codex_login_holds_only_placeholder():
    code = "import json; print(json.load(open('/run/credentials/codex/auth.json')).get('OPENAI_API_KEY'))"
    assert run("docker", "compose", "exec", "-T", "agent", "python", "-c", code).stdout.strip() == "proxy-managed"


# Limits and endpoint, through the agent's own check script


def test_check_model_proxy_script_passes():
    result = run("docker", "compose", "exec", "-T", "agent", "python", "check_model_proxy.py", check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "FAIL" not in result.stdout


def test_budget_survives_broker_restart():
    before = agent_usage()
    run("docker", "compose", "restart", "model-proxy", timeout=180)
    run("docker", "compose", "up", "-d", "--wait", "model-proxy", timeout=180)
    assert agent_usage() == before


def test_broker_has_fixed_policy_settings():
    env = dict(item.split("=", 1) for item in inspect("model-proxy")["Config"]["Env"])
    assert env["MODEL_PROXY_REQUEST_LIMIT"] == "60"
    assert env["MODEL_PROXY_MAX_OUTPUT_TOKENS"] == "4096"
    agent_env = dict(item.split("=", 1) for item in inspect("agent")["Config"]["Env"])
    assert env["MODEL_PROXY_MODEL"] == agent_env["CODEX_MODEL"]

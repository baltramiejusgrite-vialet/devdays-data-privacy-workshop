"""Step 4 network and model checks, run from the host. Safe to run repeatedly.

Requires the lab to be running: docker compose up -d --wait (from agent-security-workshop).
Key checks compare variable names and placeholders only; no secret value is printed.
The one live model request is marked `live_model` (deselect with -m "not live_model").
"""

import json
import subprocess
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
PROJECT = "devdays-agent-student-workshop"
EXPECTED_NETWORKS = {
    "agent": {"agent_net"},
    "db": {"db_net"},
    "gateway": {"agent_net", "db_net"},
    "model-proxy": {"agent_net", "egress_net"},
}


def run(*args, check=True):
    return subprocess.run(
        args, cwd=LAB_DIR, capture_output=True, text=True, check=check, stdin=subprocess.DEVNULL, timeout=180
    )


def exec_python(service, code):
    return run("docker", "compose", "exec", "-T", service, "python", "-c", code).stdout.strip()


def inspect_service(service):
    container_id = run("docker", "compose", "ps", "-q", service).stdout.strip()
    if not container_id:
        pytest.skip(f"{service} is not running; start the lab with docker compose up -d --wait")
    return json.loads(run("docker", "inspect", container_id).stdout)[0]


def env_names(container):
    return {item.split("=", 1)[0] for item in container["Config"]["Env"]}


def can_connect(host, port):
    code = (
        "import socket\n"
        "try:\n"
        f"    socket.create_connection(({host!r}, {port}), timeout=3).close(); print('open')\n"
        "except OSError:\n"
        "    print('blocked')"
    )
    return exec_python("agent", code)


@pytest.fixture(scope="session")
def containers():
    return {service: inspect_service(service) for service in EXPECTED_NETWORKS}


# Networks


@pytest.mark.parametrize("service", sorted(EXPECTED_NETWORKS))
def test_service_on_expected_networks(containers, service):
    attached = {name.removeprefix(f"{PROJECT}_") for name in containers[service]["NetworkSettings"]["Networks"]}
    assert attached == EXPECTED_NETWORKS[service]


@pytest.mark.parametrize("network,internal", [("agent_net", True), ("db_net", True), ("egress_net", False)])
def test_network_internal_flag(network, internal):
    info = json.loads(run("docker", "network", "inspect", f"{PROJECT}_{network}").stdout)[0]
    assert info["Internal"] is internal


def test_no_ports_published(containers):
    published = {s: c["HostConfig"]["PortBindings"] for s, c in containers.items() if c["HostConfig"]["PortBindings"]}
    assert published == {}


# What the agent can and cannot reach


@pytest.mark.parametrize("host,port", [("db", 5432), ("api.openai.com", 443), ("1.1.1.1", 443), ("pypi.org", 443)])
def test_agent_direct_connection_blocked(host, port):
    assert can_connect(host, port) == "blocked"


def test_agent_reaches_gateway():
    assert can_connect("gateway", 8000) == "open"


def test_agent_reaches_model_proxy():
    assert can_connect("model-proxy", 8080) == "open"


# Database gateway: read-only configuration and health check


def test_gateway_lists_projects():
    from gateway_client import gateway_request

    assert gateway_request("/projects") == (200, {"items": [
        {"project_id": 1, "title": "Conference schedule"},
        {"project_id": 2, "title": "Workshop materials"},
    ]})


def test_gateway_rejects_writes():
    from gateway_client import gateway_request

    status, _ = gateway_request("/projects", method="POST")
    assert status == 405


def test_gateway_config_mounted_read_only(containers):
    mounts = {m["Destination"]: m["RW"] for m in containers["gateway"]["Mounts"]}
    assert mounts == {"/run/gateway/connection.json": False}


def test_gateway_database_session_is_read_only():
    code = (
        "import json, psycopg\n"
        "cfg = json.load(open('/run/gateway/connection.json'))\n"
        "with psycopg.connect(**cfg) as c:\n"
        "    print(c.execute('SHOW default_transaction_read_only').fetchone()[0])"
    )
    assert exec_python("gateway", code) == "on"


def test_gateway_database_write_refused():
    code = (
        "import json, psycopg\n"
        "cfg = json.load(open('/run/gateway/connection.json'))\n"
        "try:\n"
        "    with psycopg.connect(**cfg) as c:\n"
        "        c.execute(\"UPDATE lab_public.projects SET title = title WHERE project_id = 1\")\n"
        "    print('written')\n"
        "except psycopg.errors.ReadOnlySqlTransaction:\n"
        "    print('refused')"
    )
    assert exec_python("gateway", code) == "refused"


@pytest.mark.parametrize("service", ["gateway", "model-proxy", "db"])
def test_service_has_passing_health_check(containers, service):
    assert containers[service]["Config"]["Healthcheck"]["Test"]
    assert containers[service]["State"]["Health"]["Status"] == "healthy"


# OpenAI key lives only in the model proxy


def test_key_only_in_model_proxy(containers):
    holders = sorted(s for s, c in containers.items() if "OPENAI_API_KEY" in env_names(c))
    assert holders == ["model-proxy"]


def test_agent_has_no_database_url(containers):
    assert "DATABASE_URL" not in env_names(containers["agent"])


def test_agent_credentials_hold_only_placeholder():
    code = "import json; print(json.load(open('/run/credentials/codex/auth.json')).get('OPENAI_API_KEY'))"
    assert exec_python("agent", code) == "proxy-managed"


def test_model_proxy_only_forwards_model_api():
    code = (
        "import urllib.request as u, urllib.error as e\n"
        "try:\n"
        "    u.urlopen('http://model-proxy:8080/admin', timeout=10); print('allowed')\n"
        "except e.HTTPError as err:\n"
        "    print(err.code)"
    )
    assert exec_python("agent", code) == "403"


# Earlier restrictions preserved on every service the agent can touch


@pytest.mark.parametrize("service", ["agent", "gateway", "model-proxy"])
def test_hardening_preserved(containers, service):
    host_config = containers[service]["HostConfig"]
    assert host_config["CapDrop"] == ["ALL"]
    assert "no-new-privileges:true" in host_config["SecurityOpt"]
    assert host_config["Privileged"] is False
    assert host_config["ReadonlyRootfs"] is True
    assert containers[service]["Config"]["User"] not in ("", "0", "root")


# Live check: Codex reaches OpenAI through the proxy (uses a few thousand tokens)


@pytest.mark.live_model
def test_codex_reaches_openai_through_proxy():
    result = run(
        "docker", "compose", "exec", "-T", "agent", "python", "starter.py",
        "Do not use tools or inspect files. Reply with exactly READY.",
    )
    assert result.stdout.strip() == "READY"

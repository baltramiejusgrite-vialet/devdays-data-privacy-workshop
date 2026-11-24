"""Checks the agent container hardening from the host.

Requires the lab to be running: docker compose up -d --wait (from agent-security-workshop).
"""

import json
import subprocess
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
AGENT_UID = "10001"
AGENT_GID = "10001"
ZERO_CAPS = "0000000000000000"


def run(*args, check=True):
    return subprocess.run(args, cwd=LAB_DIR, capture_output=True, text=True, check=check)


def agent_exec(*args, check=True):
    return run("docker", "compose", "exec", "-T", "agent", *args, check=check)


def agent_python(code):
    return agent_exec("python", "-c", code).stdout.strip()


@pytest.fixture(scope="session")
def container():
    container_id = run("docker", "compose", "ps", "-q", "agent").stdout.strip()
    if not container_id:
        pytest.skip("agent container is not running; start it with docker compose up -d --wait")
    return json.loads(run("docker", "inspect", container_id).stdout)[0]


@pytest.fixture(scope="session")
def proc_status():
    lines = agent_exec("cat", "/proc/self/status").stdout.splitlines()
    pairs = (line.split(":", 1) for line in lines if ":" in line)
    return {key.strip(): value.strip() for key, value in pairs}


# Requirement 1: run as UID/GID 10001


def test_configured_user_is_10001(container):
    assert container["Config"]["User"] == f"{AGENT_UID}:{AGENT_GID}"


def test_process_uid_is_10001(proc_status):
    assert proc_status["Uid"].split() == [AGENT_UID] * 4


def test_process_gid_is_10001(proc_status):
    assert proc_status["Gid"].split() == [AGENT_GID] * 4


def test_not_in_root_group():
    assert agent_exec("id", "-G").stdout.split() == [AGENT_GID]


# Requirement 2: drop all Linux capabilities


def test_cap_drop_all_configured(container):
    assert container["HostConfig"]["CapDrop"] == ["ALL"]


def test_no_capabilities_added_back(container):
    assert not container["HostConfig"]["CapAdd"]


@pytest.mark.parametrize("cap_set", ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"])
def test_process_capability_set_is_empty(proc_status, cap_set):
    assert proc_status[cap_set] == ZERO_CAPS


def test_privileged_operation_is_refused():
    result = agent_exec("chown", "root", "/tmp", check=False)
    assert result.returncode != 0
    assert "Operation not permitted" in result.stderr


# Requirement 3: enable no-new-privileges


def test_no_new_privileges_configured(container):
    assert "no-new-privileges:true" in container["HostConfig"]["SecurityOpt"]


def test_process_no_new_privs_flag_set(proc_status):
    assert proc_status["NoNewPrivs"] == "1"


def test_cannot_switch_to_root():
    result = agent_exec("sh", "-c", "su -c id root </dev/null", check=False)
    assert result.returncode != 0
    assert "uid=0" not in result.stdout


# Requirement 4: keep privileged mode disabled


def test_privileged_mode_disabled(container):
    assert container["HostConfig"]["Privileged"] is False


def test_no_host_devices_exposed(container):
    assert not container["HostConfig"]["Devices"]


# Requirement 5: preserve filesystem access


def test_workspace_is_mounted_read_write(container):
    mounts = [m for m in container["Mounts"] if m["Destination"] == "/workspace"]
    assert len(mounts) == 1
    assert mounts[0]["RW"] is True


def test_can_read_existing_workspace_file():
    assert agent_python("import pathlib; print(len(pathlib.Path('/workspace/schema.sql').read_text()) > 0)") == "True"


def test_can_create_read_delete_workspace_file():
    code = (
        "import pathlib, tempfile\n"
        "f = tempfile.NamedTemporaryFile(dir='/workspace', prefix='.hardening-', delete=False)\n"
        "f.write(b'ok'); f.close()\n"
        "p = pathlib.Path(f.name)\n"
        "content = p.read_bytes(); p.unlink()\n"
        "print(content == b'ok' and not p.exists())"
    )
    assert agent_python(code) == "True"


def test_home_directory_is_writable():
    code = "import os, pathlib; p = pathlib.Path(os.environ['HOME'], '.write-test'); p.write_text('x'); p.unlink(); print('ok')"
    assert agent_python(code) == "ok"


# Requirement 6: preserve database access


def test_database_connection_works():
    code = (
        "import os, psycopg\n"
        "with psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=10) as c:\n"
        "    print(c.execute('SELECT 1').fetchone()[0])"
    )
    assert agent_python(code) == "1"


def test_database_projects_readable():
    code = (
        "import os, psycopg\n"
        "with psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=10) as c:\n"
        "    c.read_only = True\n"
        "    print(c.execute('SELECT count(*) FROM lab_public.projects').fetchone()[0])"
    )
    assert int(agent_python(code)) >= 2

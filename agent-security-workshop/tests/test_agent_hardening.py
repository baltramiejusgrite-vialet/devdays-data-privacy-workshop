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
CREDENTIAL_DIR = "/run/credentials/codex"


def run(*args, check=True):
    # stdin closed: in an interactive terminal docker would otherwise wait on it.
    return subprocess.run(
        args, cwd=LAB_DIR, capture_output=True, text=True, check=check, stdin=subprocess.DEVNULL, timeout=60
    )


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


# Requirement 5: filesystem access (workspace read-only since step 3; /tmp is the scratch area)


def test_workspace_entry_point_is_read_only_mount(container):
    mounts = [m for m in container["Mounts"] if m["Destination"] == "/workspace/starter.py"]
    assert len(mounts) == 1
    assert mounts[0]["RW"] is False


def test_can_read_workspace_entry_point():
    assert agent_python("import pathlib; print(len(pathlib.Path('/workspace/starter.py').read_text()) > 0)") == "True"


def test_writing_to_workspace_fails():
    code = (
        "import pathlib\n"
        "try:\n"
        "    pathlib.Path('/workspace/.write-test').write_text('x')\n"
        "    print('written')\n"
        "except OSError as e:\n"
        "    print(type(e).__name__)"
    )
    assert agent_python(code) in {"OSError", "PermissionError"}


def test_writing_to_tmp_succeeds():
    code = (
        "import pathlib, tempfile\n"
        "f = tempfile.NamedTemporaryFile(dir='/tmp', prefix='.hardening-', delete=False)\n"
        "f.write(b'ok'); f.close()\n"
        "p = pathlib.Path(f.name)\n"
        "content = p.read_bytes(); p.unlink()\n"
        "print(content == b'ok' and not p.exists())"
    )
    assert agent_python(code) == "True"


def test_home_directory_is_writable():
    code = "import os, pathlib; p = pathlib.Path(os.environ['HOME'], '.write-test'); p.write_text('x'); p.unlink(); print('ok')"
    assert agent_python(code) == "ok"


# Requirement 7: read-only root filesystem


def test_read_only_root_configured(container):
    assert container["HostConfig"]["ReadonlyRootfs"] is True


@pytest.mark.parametrize("path", ["/", "/usr/local/bin", "/etc", "/run"])
def test_root_filesystem_rejects_writes(path):
    result = agent_exec("sh", "-c", f"touch {path}/.ro-test", check=False)
    assert result.returncode != 0
    assert "Read-only file system" in result.stderr


def test_root_mount_is_read_only():
    mount_options = agent_exec("sh", "-c", "awk '$2 == \"/\" {print $4}' /proc/mounts").stdout
    assert mount_options.split(",")[0] == "ro"


# Requirement 8: /tmp and /home/agent writable through temporary mounts


@pytest.mark.parametrize("path", ["/tmp", "/home/agent"])
def test_path_is_tmpfs_mount(container, path):
    assert path in container["HostConfig"]["Tmpfs"]
    fs_type = agent_exec("sh", "-c", f"awk '$2 == \"{path}\" {{print $3}}' /proc/mounts").stdout.strip()
    assert fs_type == "tmpfs"


@pytest.mark.parametrize("path", ["/tmp", "/home/agent"])
def test_temporary_mount_is_writable(path):
    code = f"import pathlib; p = pathlib.Path('{path}/.tmpfs-test'); p.write_text('x'); p.unlink(); print('ok')"
    assert agent_python(code) == "ok"


def test_home_owned_by_agent():
    assert agent_exec("stat", "-c", "%u:%g", "/home/agent").stdout.strip() == f"{AGENT_UID}:{AGENT_GID}"


# Requirement 9: credential volume mounted read-only


def test_credential_volume_mounted_read_only(container):
    mounts = [m for m in container["Mounts"] if m["Destination"] == CREDENTIAL_DIR]
    assert len(mounts) == 1
    assert mounts[0]["Type"] == "volume"
    assert mounts[0]["RW"] is False


def test_credentials_are_readable():
    assert agent_exec("test", "-r", f"{CREDENTIAL_DIR}/auth.json", check=False).returncode == 0


def test_credentials_cannot_be_changed():
    result = agent_exec("sh", "-c", f"touch {CREDENTIAL_DIR}/auth.json {CREDENTIAL_DIR}/.new", check=False)
    assert result.returncode != 0
    assert "Read-only file system" in result.stderr


def test_codex_sees_its_login():
    agent_python(
        "import sys; sys.argv = ['x']; import importlib.util as u; "
        "s = u.spec_from_file_location('starter', '/workspace/starter.py'); m = u.module_from_spec(s); "
        "s.loader.exec_module(m); m.link_credentials()"
    )
    status = agent_exec("codex", "login", "status")
    assert "API key configured" in status.stdout + status.stderr


# Requirement 6: database access preserved, through the gateway since step 4


def test_database_connection_works():
    code = (
        "import json, os, urllib.request as u\n"
        "print(json.load(u.urlopen(os.environ['GATEWAY_URL'] + '/health', timeout=10))['database'])"
    )
    assert agent_python(code) == "True"


def test_database_projects_readable():
    code = (
        "import json, os, urllib.request as u\n"
        "print(len(json.load(u.urlopen(os.environ['GATEWAY_URL'] + '/projects', timeout=10))))"
    )
    assert int(agent_python(code)) >= 2

"""Step 3 isolation checks, run from the host against the running agent container.

Safe to run repeatedly: every check only reads, and the one write attempt targets a
read-only path and cleans up nothing because nothing can be created.
Requires the lab to be running: docker compose up -d --wait (from agent-security-workshop).
"""

import json
import subprocess
from pathlib import Path

import pytest

LAB_DIR = Path(__file__).resolve().parent.parent
ALLOWED_MOUNTS = {
    "/workspace/starter.py": False,
    "/run/credentials/codex": False,
}
HOST_PROJECT_FILES = [
    "/workspace/docker-compose.yml",
    "/workspace/Dockerfile",
    "/workspace/schema.sql",
    "/workspace/snippets/step-3-isolation.txt",
    "/workspace/tests/test_agent_isolation.py",
    "/workspace/average_salary_by_company.csv",
]
SOCKET_PATHS = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/host-services/docker.proxy.sock",
    "/run/host-services/ssh-auth.sock",
]
HOST_PATH_MARKERS = ["/mnt/host", "/mnt/c", "/mnt/wsl", "/host_mnt", "/run/desktop", "/Users", "/home/docker"]


def run(*args, check=True):
    # stdin closed: in an interactive terminal docker would otherwise wait on it.
    return subprocess.run(
        args, cwd=LAB_DIR, capture_output=True, text=True, check=check, stdin=subprocess.DEVNULL, timeout=60
    )


def agent_python(code):
    return run("docker", "compose", "exec", "-T", "agent", "python", "-c", code).stdout.strip()


@pytest.fixture(scope="session")
def container():
    container_id = run("docker", "compose", "ps", "-q", "agent").stdout.strip()
    if not container_id:
        pytest.skip("agent container is not running; start it with docker compose up -d --wait")
    return json.loads(run("docker", "inspect", container_id).stdout)[0]


# Only the required workspace and read-only credentials are exposed


def test_only_allowed_mounts(container):
    assert {m["Destination"]: m["RW"] for m in container["Mounts"]} == ALLOWED_MOUNTS


def test_project_folder_not_mounted(container):
    assert not [m for m in container["Mounts"] if m["Destination"] == "/workspace"]


def test_entry_point_readable():
    assert agent_python("import pathlib; print(pathlib.Path('/workspace/starter.py').is_file())") == "True"


def test_workspace_contains_only_entry_point():
    assert agent_python("import os; print(sorted(os.listdir('/workspace')))") == "['starter.py']"


# Host files are inaccessible


@pytest.mark.parametrize("path", HOST_PROJECT_FILES)
def test_host_project_file_inaccessible(path):
    code = (
        "from pathlib import Path\n"
        "try:\n"
        f"    Path({path!r}).read_bytes()\n"
        "    print('readable')\n"
        "except (FileNotFoundError, PermissionError):\n"
        "    print('inaccessible')"
    )
    assert agent_python(code) == "inaccessible"


def test_no_host_directory_mounted():
    mount_points = agent_python("print('\\n'.join(l.split()[1] for l in open('/proc/mounts')))").splitlines()
    leaked = [p for p in mount_points if any(p.startswith(marker) for marker in HOST_PATH_MARKERS)]
    assert leaked == []


def test_no_bind_mount_except_entry_point(container):
    binds = [m["Destination"] for m in container["Mounts"] if m["Type"] == "bind"]
    assert binds == ["/workspace/starter.py"]


# Docker and SSH sockets are blocked


@pytest.mark.parametrize("path", SOCKET_PATHS)
def test_socket_absent(path):
    assert agent_python(f"import os; print(os.path.exists({path!r}))") == "False"


def test_no_unix_sockets_reachable_from_mounts():
    code = (
        "import os, stat\n"
        "found = []\n"
        "for root in ('/run', '/var/run', '/tmp', '/workspace', '/home/agent'):\n"
        "    for dirpath, _, files in os.walk(root):\n"
        "        for name in files:\n"
        "            p = os.path.join(dirpath, name)\n"
        "            try:\n"
        "                if stat.S_ISSOCK(os.lstat(p).st_mode): found.append(p)\n"
        "            except OSError: pass\n"
        "print(found)"
    )
    assert agent_python(code) == "[]"


def test_ssh_agent_not_forwarded():
    assert agent_python("import os; print('SSH_AUTH_SOCK' in os.environ)") == "False"


def test_docker_host_not_set():
    assert agent_python("import os; print('DOCKER_HOST' in os.environ)") == "False"


# Host namespaces are not shared


@pytest.mark.parametrize("mode", ["PidMode", "IpcMode", "UTSMode", "UsernsMode", "NetworkMode"])
def test_namespace_not_host(container, mode):
    assert container["HostConfig"][mode] != "host"


def test_ipc_and_cgroup_private(container):
    assert container["HostConfig"]["IpcMode"] == "private"
    assert container["HostConfig"]["CgroupnsMode"] == "private"


def test_pid_namespace_isolated():
    pids = agent_python("import os; print(sorted(int(p) for p in os.listdir('/proc') if p.isdigit())[:1])")
    process_count = int(agent_python("import os; print(sum(p.isdigit() for p in os.listdir('/proc')))"))
    assert pids == "[1]"
    assert process_count < 20


def test_pid_1_is_container_process():
    assert "python" in agent_python("print(open('/proc/1/cmdline').read().replace('\\0', ' '))")


# Existing restrictions and database access are preserved


def test_existing_restrictions_preserved(container):
    host_config = container["HostConfig"]
    assert container["Config"]["User"] == "10001:10001"
    assert host_config["CapDrop"] == ["ALL"]
    assert "no-new-privileges:true" in host_config["SecurityOpt"]
    assert host_config["Privileged"] is False
    assert host_config["ReadonlyRootfs"] is True


def test_database_still_reachable():
    code = (
        "import json, os, urllib.request as u\n"
        "print(len(json.load(u.urlopen(os.environ['GATEWAY_URL'] + '/projects', timeout=10))['items']))"
    )
    assert int(agent_python(code)) >= 2

from pathlib import Path

import psycopg
import pytest

ENV_FILE = Path(__file__).resolve().parent.parent / ".env.readonly"


def read_env_file(path):
    pairs = (line.split("=", 1) for line in path.read_text(encoding="utf-8-sig").splitlines() if "=" in line)
    return {key.strip(): value.strip() for key, value in pairs}


@pytest.fixture(scope="session")
def readonly_settings():
    if not ENV_FILE.exists():
        pytest.skip(f"{ENV_FILE.name} not found; create the workshop_readonly user first")
    return read_env_file(ENV_FILE)


@pytest.fixture
def readonly_conn(readonly_settings):
    conn = psycopg.connect(
        host=readonly_settings["DB_HOST"],
        port=readonly_settings["DB_PORT"],
        dbname=readonly_settings["DB_NAME"],
        user=readonly_settings["DB_USER"],
        password=readonly_settings["DB_PASSWORD"],
        autocommit=True,
        connect_timeout=5,
    )
    yield conn
    conn.close()

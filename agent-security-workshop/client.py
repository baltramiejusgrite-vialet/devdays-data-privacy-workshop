"""Agent's gateway client. Usage: python3 client.py /me /companies/1/salary-summary ...

Sends the agent's token from /run/identity/access.json (never printed) and prints,
for each path, the HTTP status, the gateway's request ID and the JSON response.
"""

import json
import os
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = os.environ["GATEWAY_URL"]


def load_token():
    with open("/run/identity/access.json") as f:
        return json.load(f)["gateway_token"]


def call(path, token):
    request = Request(BASE + path, headers={"Authorization": "Bearer " + token})
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, response.headers.get("X-Request-ID"), json.load(response)
    except HTTPError as error:
        return error.code, error.headers.get("X-Request-ID"), json.load(error)


def main(paths):
    if not paths:
        sys.exit("usage: python3 client.py <path> [<path> ...]")
    token = load_token()
    for path in paths:
        status, request_id, body = call(path, token)
        print(f"GET {path} -> {status} request_id={request_id} {json.dumps(body)}")


if __name__ == "__main__":
    main(sys.argv[1:])

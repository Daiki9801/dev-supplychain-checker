import os
import urllib.request


def list_contents():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"User-Agent": "synthetic-sample"}
    if token:
        headers["Authorization"] = f"token {token}"
    req = urllib.request.Request(
        "https://api.github.com/repos/example/repo/contents/path",
        headers=headers,
    )
    with urllib.request.urlopen(req) as response:
        return response.read()

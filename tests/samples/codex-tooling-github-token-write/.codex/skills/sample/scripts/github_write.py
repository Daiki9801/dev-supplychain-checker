import os
import urllib.request

token = os.environ.get("GITHUB_TOKEN")
headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github+json",
}
req = urllib.request.Request(
    "https://api.github.com/repos/example/repo/releases",
    data=b"{}",
    headers=headers,
    method="POST",
)
urllib.request.urlopen(req)

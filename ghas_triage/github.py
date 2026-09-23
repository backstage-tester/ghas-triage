"""Minimal GitHub REST client for GHAS alerts + code context."""
from __future__ import annotations

import sys
from functools import lru_cache

import requests

API = "https://api.github.com"


class GitHub:
    def __init__(self, token: str, api: str = API):
        self.api = api.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _paginate(self, path: str, params: dict | None = None, limit: int | None = None) -> list[dict]:
        url, out = f"{self.api}{path}", []
        params = {"per_page": 100, **(params or {})}
        while url:
            r = self.s.get(url, params=params, timeout=30)
            if r.status_code in (403, 404):
                # Feature not enabled, or token lacks the permission. Don't fail the run.
                msg = r.json().get("message", "") if r.headers.get("content-type", "").startswith("application/json") else ""
                print(f"warning: {path} -> HTTP {r.status_code} {msg}".rstrip(), file=sys.stderr)
                return out
            r.raise_for_status()
            out.extend(r.json())
            if limit and len(out) >= limit:
                return out[:limit]
            url, params = r.links.get("next", {}).get("url"), None  # next URL already has params
        return out

    def code_scanning_alerts(self, repo: str, limit: int | None = None) -> list[dict]:
        return self._paginate(f"/repos/{repo}/code-scanning/alerts", {"state": "open"}, limit)

    def secret_scanning_alerts(self, repo: str, limit: int | None = None) -> list[dict]:
        return self._paginate(f"/repos/{repo}/secret-scanning/alerts", {"state": "open"}, limit)

    def dependabot_alerts(self, repo: str, limit: int | None = None) -> list[dict]:
        return self._paginate(f"/repos/{repo}/dependabot/alerts", {"state": "open"}, limit)

    def secret_location(self, locations_url: str) -> dict | None:
        r = self.s.get(locations_url, params={"per_page": 10}, timeout=30)
        if not r.ok:
            return None
        for loc in r.json():
            if loc.get("type") == "commit":
                return loc.get("details")
        return None

    @lru_cache(maxsize=256)
    def file_text(self, repo: str, path: str, ref: str) -> str | None:
        r = self.s.get(f"{self.api}/repos/{repo}/contents/{path}", params={"ref": ref},
                       headers={"Accept": "application/vnd.github.raw"}, timeout=30)
        return r.text if r.ok else None

    def snippet(self, repo: str, path: str, ref: str, start: int, end: int | None = None,
                radius: int = 20, max_chars: int = 6000) -> str | None:
        text = self.file_text(repo, path, ref)
        if text is None:
            return None
        lines = text.splitlines()
        end = end or start
        lo, hi = max(1, start - radius), min(len(lines), end + radius)
        marked = [f"{'>' if start <= n <= end else ' '}{n:5d} | {lines[n - 1]}" for n in range(lo, hi + 1)]
        return "\n".join(marked)[:max_chars]

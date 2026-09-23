"""End-to-end tests with a fake GitHub and two fake /v1/systemone servers:
one answering in TypeSafe's shape ("answers") and one in a grouped Laya shape."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from ghas_triage import __main__ as cli
from ghas_triage.backends import DecisionBackend, FatalBackendError, normalize_answers
from ghas_triage.triage import collect, ranked, run

SECRET = "ghp_REALLOOKINGTOKEN1234567890abcdef"
SEEN_STATES: list = []


def fake_answers(state: dict, questions: dict) -> dict:
    """Heuristic stand-in for the model: test paths look like noise, src/ looks real."""
    text = json.dumps(state)
    is_test = "tests/" in text or "example" in text
    ans = {}
    for qid, q in questions.items():
        if q["type"] == "noul":
            hi = qid in {"test_code", "test_or_example", "placeholder", "dev_only"}
            ans[qid] = {"type": "noul", "noul": (0.9 if is_test else 0.1) if hi else (0.2 if is_test else 0.9)}
        elif q["type"] == "score":
            ans[qid] = {"type": "score", "score": 0.5 if is_test else len(q["criteria"]) - 1.5}
        else:
            opts = list(q["criteria"])
            pick = opts[-1] if is_test else opts[0]
            ans[qid] = {"type": "choice", "choice": pick, "confidence": 0.8,
                        "probabilities": {o: (0.8 if o == pick else 0.1) for o in opts}}
    return ans


def make_server(shape: str, expect_key: str | None):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            if expect_key and self.headers.get("Authorization") != f"Bearer {expect_key}":
                self.send_response(401); self.end_headers(); return
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert self.path == "/v1/systemone" and body["model"]
            SEEN_STATES.append(body["state"])
            ans = fake_answers(body["state"], body["questions"])
            if shape == "typesafe":
                resp = {"model": "jev-1.13.0", "answers": ans, "usage": {"input_tokens": 300}}
            else:  # grouped laya-style
                resp = {"model": "laya-multilingual"}
                for qid, a in ans.items():
                    resp.setdefault(a["type"] + "s", {})[qid] = {k: v for k, v in a.items() if k != "type"}
            data = json.dumps(resp).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


class FakeGitHub:
    FILES = {
        "src/api/users.py": "\n".join(f"line {n}" for n in range(1, 60)).replace(
            "line 30", 'cursor.execute("SELECT * FROM users WHERE id=" + request.args["id"])'),
        "tests/test_utils.py": "\n".join(f"line {n}" for n in range(1, 40)),
        "deploy/prod.env": f"DB_HOST=db\nGITHUB_TOKEN={SECRET}\nREGION=us-west-2",
    }

    def __init__(self, *_):
        pass

    def code_scanning_alerts(self, repo, limit=None):
        mk = lambda n, path, sev: {
            "number": n, "html_url": f"https://github.com/{repo}/security/code-scanning/{n}",
            "tool": {"name": "CodeQL"},
            "rule": {"id": "py/sql-injection", "name": "SQL injection", "security_severity_level": sev,
                     "description": "Building SQL from user input"},
            "most_recent_instance": {"commit_sha": "abc", "message": {"text": "user-provided value"},
                                     "location": {"path": path, "start_line": 30, "end_line": 30}}}
        return [mk(1, "tests/test_utils.py", "high"), mk(2, "src/api/users.py", "critical")]

    def secret_scanning_alerts(self, repo, limit=None):
        return [{"number": 7, "secret": SECRET, "secret_type": "github_personal_access_token",
                 "secret_type_display_name": "GitHub PAT", "validity": "active",
                 "locations_url": "x", "html_url": f"https://github.com/{repo}/security/secret-scanning/7"}]

    def dependabot_alerts(self, repo, limit=None):
        return [{"number": 3, "html_url": "https://github.com/x/y/security/dependabot/3",
                 "dependency": {"package": {"ecosystem": "npm", "name": "lodash"},
                                "manifest_path": "package-lock.json", "scope": "runtime"},
                 "security_advisory": {"summary": "Prototype pollution", "severity": "high",
                                       "epss": [{"percentage": 0.02}]},
                 "security_vulnerability": {"vulnerable_version_range": "< 4.17.21",
                                            "first_patched_version": {"identifier": "4.17.21"}}}]

    def secret_location(self, _url):
        return {"path": "deploy/prod.env", "start_line": 2, "end_line": 2, "commit_sha": "abc"}

    def snippet(self, repo, path, ref, start, end=None, radius=20, max_chars=6000):
        lines = self.FILES[path].splitlines()
        lo, hi = max(1, start - radius), min(len(lines), (end or start) + radius)
        return "\n".join(f"{n:5d} | {lines[n - 1]}" for n in range(lo, hi + 1))


@pytest.fixture
def servers():
    jev, jev_url = make_server("typesafe", expect_key="jev-key")
    laya, laya_url = make_server("laya", expect_key=None)
    yield jev_url, laya_url
    jev.shutdown(); laya.shutdown()


def test_ranking_and_secret_redaction(servers):
    jev_url, _ = servers
    SEEN_STATES.clear()
    items = collect(FakeGitHub(), "acme/app", ["code", "secret", "dependabot"], None)
    run(items, DecisionBackend("jev", jev_url, api_key="jev-key"))
    order = [(i.kind, i.number) for i in ranked(items, "jev")]
    assert order[-1] == ("code", 1), "test-file finding should rank last"
    assert ("code", 2) in order[:2] and ("secret", 7) in order[:2]
    assert items[0].results["jev"].action == "review_dismiss"
    # The raw secret must never leave the process
    assert SEEN_STATES and all(SECRET not in json.dumps(s) for s in SEEN_STATES)
    assert any("<REDACTED>" in json.dumps(s) for s in SEEN_STATES)


def test_switch_and_compare_via_cli(servers, tmp_path, monkeypatch):
    jev_url, laya_url = servers
    monkeypatch.setattr(cli, "GitHub", FakeGitHub)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("JEV_BASE_URL", jev_url)
    monkeypatch.setenv("TYPESAFE_API_KEY", "jev-key")
    monkeypatch.setenv("LAYA_BASE_URL", laya_url)
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    out = tmp_path / "triage"

    assert cli.main(["--repo", "acme/app", "--backend", "laya", "--out", str(out)]) == 0
    assert "laya-multilingual" in (tmp_path / "triage.md").read_text()

    assert cli.main(["--repo", "acme/app", "--backend", "jev,laya", "--out", str(out)]) == 0
    md = (tmp_path / "triage.md").read_text()
    assert "## jev vs laya" in md and "Same recommendation | 4/4 (100%)" in md
    data = json.loads((tmp_path / "triage.json").read_text())
    assert set(data["alerts"][0]["results"]) == {"jev", "laya"}
    assert SECRET not in md and SECRET not in (tmp_path / "triage.json").read_text()
    assert summary.read_text().count("# GHAS triage") == 2


def test_auth_failure_is_reported_not_fatal(servers):
    jev_url, _ = servers
    items = collect(FakeGitHub(), "acme/app", ["dependabot"], None)
    run(items, DecisionBackend("jev", jev_url, api_key="wrong"))
    r = items[0].results["jev"]
    assert r.error and "401" in r.error and r.priority is None


def test_normalize_rejects_unknown_shape():
    with pytest.raises(FatalBackendError):
        normalize_answers({"foo": 1})
    assert normalize_answers({"nouls": {"a": 0.7}}) == {"a": {"type": "noul", "noul": 0.7}}

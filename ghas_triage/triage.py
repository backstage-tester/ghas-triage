"""Turn raw GHAS alerts into decision-model state, ask the backend, rank the results."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .backends import Decision, DecisionBackend
from .github import GitHub
from .questions import BY_KIND

SEVERITY = {"critical": 1.0, "high": 0.8, "medium": 0.5, "moderate": 0.5, "low": 0.25,
            "error": 0.5, "warning": 0.3, "note": 0.1}
VALIDITY = {"active": 1.0, "unknown": 0.7, "inactive": 0.3}


@dataclass
class Item:
    kind: str                 # code | secret | dependabot
    number: int
    title: str
    severity: str
    location: str
    url: str
    state: dict               # what the decision model sees
    results: dict = field(default_factory=dict)   # backend name -> Result


@dataclass
class Result:
    decision: Decision | None
    priority: float | None
    action: str | None
    confidence: float | None
    signals: dict
    error: str | None = None


# ---------- build items (GitHub -> model state) ----------

def code_item(gh: GitHub | None, repo: str, a: dict) -> Item:
    rule, inst = a.get("rule", {}), a.get("most_recent_instance", {})
    loc = inst.get("location", {})
    path, start, end = loc.get("path", ""), loc.get("start_line") or 1, loc.get("end_line")
    sev = (rule.get("security_severity_level") or rule.get("severity") or "note").lower()
    snippet = gh.snippet(repo, path, inst.get("commit_sha") or inst.get("ref", "HEAD"), start, end) if gh and path else None
    state = {
        "alert_type": "code_scanning",
        "tool": a.get("tool", {}).get("name"),
        "rule_id": rule.get("id"),
        "rule_name": rule.get("name") or rule.get("description"),
        "rule_description": (rule.get("full_description") or rule.get("description") or "")[:1500],
        "rule_tags": rule.get("tags", []),
        "severity": sev,
        "message": inst.get("message", {}).get("text", "")[:1000],
        "file": path,
        "lines": f"{start}-{end or start}",
        "code_snippet": snippet or "(unavailable)",
    }
    return Item("code", a["number"], state["rule_name"] or state["rule_id"] or "code alert", sev,
                f"{path}:{start}", a.get("html_url", ""), state)


def _redact(text: str, secret: str | None) -> str:
    if not secret:
        return text
    for part in {secret, *[p for p in secret.splitlines() if len(p) >= 6]}:
        text = text.replace(part, "<REDACTED>")
    return text


def secret_item(gh: GitHub | None, repo: str, a: dict) -> Item:
    secret = a.pop("secret", None)  # never keep the raw value around, never send it anywhere
    loc = gh.secret_location(a["locations_url"]) if gh and a.get("locations_url") else None
    path = (loc or {}).get("path", "")
    start, end = (loc or {}).get("start_line") or 1, (loc or {}).get("end_line")
    snippet = None
    if gh and loc and path:
        raw = gh.snippet(repo, path, loc.get("commit_sha") or "HEAD", start, end, radius=8)
        snippet = _redact(raw, secret) if raw else None
    validity = (a.get("validity") or "unknown").lower()
    state = {
        "alert_type": "secret_scanning",
        "secret_type": a.get("secret_type_display_name") or a.get("secret_type"),
        "validity": validity,
        "publicly_leaked": a.get("publicly_leaked", False),
        "push_protection_bypassed": a.get("push_protection_bypassed", False),
        "file": path or "(unknown)",
        "context_redacted": snippet or "(unavailable)",
    }
    return Item("secret", a["number"], state["secret_type"] or "secret", validity,
                f"{path}:{start}" if path else "(unknown)", a.get("html_url", ""), state)


def _epss(v) -> float | None:
    if isinstance(v, list):
        v = v[0] if v else None
    return v.get("percentage") if isinstance(v, dict) else None


def dependabot_item(_gh: GitHub | None, _repo: str, a: dict) -> Item:
    dep, adv, vuln = a.get("dependency", {}), a.get("security_advisory", {}), a.get("security_vulnerability", {})
    pkg = dep.get("package", {})
    sev = (adv.get("severity") or vuln.get("severity") or "low").lower()
    state = {
        "alert_type": "dependabot",
        "ecosystem": pkg.get("ecosystem"),
        "package": pkg.get("name"),
        "manifest_path": dep.get("manifest_path"),
        "scope": dep.get("scope"),                       # runtime | development
        "relationship": dep.get("relationship"),         # direct | transitive (when available)
        "severity": sev,
        "cvss": (adv.get("cvss") or {}).get("score"),
        "epss": _epss(adv.get("epss")),
        "advisory_summary": adv.get("summary"),
        "advisory_description": (adv.get("description") or "")[:1500],
        "vulnerable_range": vuln.get("vulnerable_version_range"),
        "patched_version": (vuln.get("first_patched_version") or {}).get("identifier"),
    }
    return Item("dependabot", a["number"], f"{pkg.get('name')}: {adv.get('summary', '')}"[:120], sev,
                dep.get("manifest_path", ""), a.get("html_url", ""), state)


BUILDERS = {"code": code_item, "secret": secret_item, "dependabot": dependabot_item}


def collect(gh: GitHub, repo: str, kinds: list[str], limit: int | None) -> list[Item]:
    fetch = {"code": gh.code_scanning_alerts, "secret": gh.secret_scanning_alerts,
             "dependabot": gh.dependabot_alerts}
    items: list[Item] = []
    for kind in kinds:
        raw = fetch[kind](repo, limit)
        with ThreadPoolExecutor(max_workers=8) as ex:  # snippet fetches are I/O bound
            items.extend(ex.map(lambda a, k=kind: BUILDERS[k](gh, repo, a), raw))
    return items


# ---------- scoring ----------

def _noul(ans: dict, q: str, default: float = 0.5) -> float:
    v = (ans.get(q) or {}).get("noul")
    return float(v) if v is not None else default


def _score01(ans: dict, q: str, kind: str, default: float = 0.5) -> float:
    v = (ans.get(q) or {}).get("score")
    if v is None:
        return default
    levels = len(BY_KIND[kind][q]["criteria"])
    return max(0.0, min(1.0, float(v) / (levels - 1)))


def score(item: Item, d: Decision) -> Result:
    ans = d.answers
    act = ans.get("action") or {}
    if item.kind == "code":
        sev = SEVERITY.get(item.severity, 0.3)
        tp, reach, test = _noul(ans, "true_positive"), _noul(ans, "untrusted_input"), _noul(ans, "test_code")
        expl = _score01(ans, "exploitability", "code")
        p = sev * (0.2 + 0.8 * tp) * (0.4 + 0.6 * reach) * (1 - 0.75 * test) * (0.5 + 0.5 * expl)
        signals = {"true_pos": tp, "reachable": reach, "test_code": test, "exploitability": expl}
    elif item.kind == "secret":
        val = VALIDITY.get(item.severity, 0.7)
        test, ph, prod = _noul(ans, "test_or_example"), _noul(ans, "placeholder"), _noul(ans, "production_config")
        leaked = 1.0 if item.state.get("publicly_leaked") else 0.0
        p = val * (1 - 0.8 * max(test, ph)) * (0.6 + 0.4 * max(prod, leaked))
        signals = {"test_or_example": test, "placeholder": ph, "prod_config": prod}
    else:
        sev = SEVERITY.get(item.severity, 0.3)
        dev, used = _noul(ans, "dev_only"), _noul(ans, "vuln_path_likely_used")
        urg = _score01(ans, "urgency", "dependabot")
        p = sev * (1 - 0.7 * dev) * (0.4 + 0.6 * used) * (0.5 + 0.5 * urg)
        signals = {"dev_only": dev, "vuln_used": used, "urgency": urg}
    return Result(d, round(100 * p, 1), act.get("choice"), act.get("confidence"), signals)


def run(items: list[Item], backend: DecisionBackend, workers: int = 8) -> None:
    def one(item: Item) -> None:
        try:
            d = backend.ask(item.state, BY_KIND[item.kind])
            item.results[backend.name] = score(item, d)
        except Exception as e:  # keep going; failures show up in the report
            item.results[backend.name] = Result(None, None, None, None, {}, error=str(e)[:300])

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(one, items))


def ranked(items: list[Item], backend: str) -> list[Item]:
    return sorted(items, key=lambda i: -(i.results.get(backend).priority or -1)
                  if i.results.get(backend) else 1)

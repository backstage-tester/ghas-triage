"""Markdown + JSON output. Markdown is written so it renders well as a GitHub job summary."""
from __future__ import annotations

import json
import statistics
from dataclasses import asdict
from datetime import datetime, timezone

from .triage import Item, ranked

KIND_LABEL = {"code": "Code", "secret": "Secret", "dependabot": "Dep"}
DISMISS = "review_dismiss"
ACTION_BADGE = {"fix_now": "🔴 fix now", "rotate_now": "🔴 rotate now", "upgrade_now": "🔴 upgrade now",
                "fix_later": "🟡 fix later", "upgrade_later": "🟡 upgrade later", "investigate": "🟡 investigate",
                DISMISS: "⚪ review → dismiss"}


def _cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def _latencies(items: list[Item], b: str) -> list[float]:
    return [r.decision.latency_ms for i in items if (r := i.results.get(b)) and r.decision]


def markdown(repo: str, items: list[Item], backends: list[str], top: int = 50) -> str:
    primary = backends[0]
    out = [f"# GHAS triage: `{repo}`", ""]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    for b in backends:
        res = [i.results[b] for i in items if b in i.results]
        ok = [r for r in res if r.decision]
        lat = _latencies(items, b)
        model = next((r.decision.model for r in ok if r.decision.model), "?")
        dismiss = sum(r.action == DISMISS for r in ok)
        urgent = sum((r.action or "").endswith("_now") for r in ok)
        out.append(
            f"**{b}** (`{model}`): {len(ok)}/{len(res)} alerts triaged · "
            f"🔴 {urgent} urgent · ⚪ {dismiss} likely noise ({(100 * dismiss / len(ok)) if ok else 0:.0f}%) · "
            f"median {statistics.median(lat) if lat else 0:.0f} ms/alert"
        )
    out += ["", f"_Generated {now}. Model output is advisory: nothing is dismissed automatically._", ""]

    by_kind = {k: sum(i.kind == k for i in items) for k in KIND_LABEL}
    out.append("Alerts: " + " · ".join(f"{KIND_LABEL[k]} {n}" for k, n in by_kind.items()))
    out += ["", f"## Ranked by `{primary}`", "",
            "| # | Priority | Type | Alert | Location | Recommendation | Signals |",
            "|---:|---:|---|---|---|---|---|"]
    for n, i in enumerate(ranked(items, primary)[:top], 1):
        r = i.results.get(primary)
        if not r or r.error:
            rec, pri, sig = f"⚠️ error: {_cell((r.error if r else 'not run')[:80])}", "-", ""
        else:
            conf = f" ({r.confidence:.0%})" if r.confidence is not None else ""
            rec = ACTION_BADGE.get(r.action, r.action or "?") + conf
            pri = f"{r.priority:.0f}"
            sig = " · ".join(f"{k} {v:.2f}" for k, v in r.signals.items())
        title = f"[#{i.number} {_cell(i.title[:70])}]({i.url})" if i.url else f"#{i.number} {_cell(i.title[:70])}"
        out.append(f"| {n} | {pri} | {KIND_LABEL[i.kind]} {i.severity} | {title} | `{_cell(i.location)}` | {rec} | {sig} |")

    if len(backends) == 2:
        out += compare_section(items, *backends)
    return "\n".join(out) + "\n"


def compare_section(items: list[Item], a: str, b: str) -> list[str]:
    both = [i for i in items if (ra := i.results.get(a)) and (rb := i.results.get(b))
            and ra.decision and rb.decision]
    if not both:
        return ["", f"## {a} vs {b}", "", "_No alerts were triaged by both backends._"]
    agree = [i for i in both if i.results[a].action == i.results[b].action]
    diffs = [abs(i.results[a].priority - i.results[b].priority) for i in both]
    la, lb = _latencies(items, a), _latencies(items, b)
    out = ["", f"## {a} vs {b}", "",
           "| Metric | Value |", "|---|---|",
           f"| Same recommendation | {len(agree)}/{len(both)} ({100 * len(agree) / len(both):.0f}%) |",
           f"| Mean priority gap | {statistics.mean(diffs):.1f} points |",
           f"| Median latency | {a}: {statistics.median(la):.0f} ms · {b}: {statistics.median(lb):.0f} ms |"]
    disagree = [i for i in both if i not in agree]
    if disagree:
        out += ["", "<details><summary>Disagreements</summary>", "",
                f"| Alert | {a} | {b} |", "|---|---|---|"]
        for i in disagree[:30]:
            ra, rb = i.results[a], i.results[b]
            out.append(f"| [#{i.number} {_cell(i.title[:50])}]({i.url}) | {ra.action} ({ra.priority:.0f}) "
                       f"| {rb.action} ({rb.priority:.0f}) |")
        out += ["", "</details>"]
    return out


def to_json(repo: str, items: list[Item], backends: list[str]) -> str:
    def res(r):
        d = asdict(r)
        if r.decision:
            d["decision"] = {"model": r.decision.model, "latency_ms": round(r.decision.latency_ms, 1),
                             "answers": r.decision.answers, "usage": r.decision.usage}
        return d

    rows = [{"kind": i.kind, "number": i.number, "title": i.title, "severity": i.severity,
             "location": i.location, "url": i.url,
             "results": {b: res(r) for b, r in i.results.items()}}
            for i in ranked(items, backends[0])]
    return json.dumps({"repo": repo, "backends": backends, "alerts": rows}, indent=2)

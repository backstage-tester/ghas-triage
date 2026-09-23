"""CLI: python -m ghas_triage --repo owner/name [--backend jev|laya|jev,laya]"""
from __future__ import annotations

import argparse
import os
import sys

from . import report
from .backends import BACKENDS, get_backend
from .github import GitHub
from .triage import collect, run


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ghas_triage", description="Rank open GHAS alerts with Jev or Laya.")
    p.add_argument("--repo", required=True, help="owner/name")
    p.add_argument("--backend", default=os.getenv("TRIAGE_BACKEND", "jev"),
                   help=f"one of {', '.join(BACKENDS)}, or two comma-separated to compare (e.g. jev,laya)")
    p.add_argument("--types", default="code,secret,dependabot", help="alert types to include")
    p.add_argument("--limit", type=int, default=None, help="max alerts per type")
    p.add_argument("--top", type=int, default=50, help="rows in the markdown table")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--out", default="triage", help="output prefix: writes <out>.md and <out>.json")
    args = p.parse_args(argv)

    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if not token:
        p.error("set GITHUB_TOKEN (needs read access to code scanning, secret scanning, Dependabot alerts, contents)")

    names = [b.strip() for b in args.backend.split(",") if b.strip()]
    if not 1 <= len(names) <= 2:
        p.error("--backend takes one backend or two to compare")
    backends = [get_backend(n) for n in names]
    kinds = [k.strip() for k in args.types.split(",")]
    if bad := set(kinds) - {"code", "secret", "dependabot"}:
        p.error(f"unknown types: {', '.join(sorted(bad))}")

    items = collect(GitHub(token), args.repo, kinds, args.limit)
    print(f"collected {len(items)} open alerts from {args.repo}", file=sys.stderr)
    for b in backends:
        print(f"triaging with {b.name} at {b.base_url} ...", file=sys.stderr)
        run(items, b, workers=args.workers)

    md = report.markdown(args.repo, items, names, top=args.top)
    with open(f"{args.out}.md", "w") as f:
        f.write(md)
    with open(f"{args.out}.json", "w") as f:
        f.write(report.to_json(args.repo, items, names))
    if summary := os.getenv("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as f:
            f.write(md)
    print(f"wrote {args.out}.md and {args.out}.json", file=sys.stderr)

    failed = sum(1 for i in items for r in i.results.values() if r.error)
    return 1 if items and failed == len(items) * len(backends) else 0


if __name__ == "__main__":
    sys.exit(main())

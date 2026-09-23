# GHAS triage: `acme/app`

**jev** (`jev-1.13.0`): 4/4 alerts triaged · 🔴 3 urgent · ⚪ 1 likely noise (25%) · median 4 ms/alert
**laya** (`laya-multilingual`): 4/4 alerts triaged · 🔴 3 urgent · ⚪ 1 likely noise (25%) · median 4 ms/alert

_Generated 2026-09-23 04:06 UTC. Model output is advisory: nothing is dismissed automatically._

Alerts: Code 2 · Secret 1 · Dep 1

## Ranked by `jev`

| # | Priority | Type | Alert | Location | Recommendation | Signals |
|---:|---:|---|---|---|---|---|
| 1 | 88 | Secret active | [#7 GitHub PAT](https://github.com/acme/app/security/secret-scanning/7) | `deploy/prod.env:2` | 🔴 rotate now (80%) | test_or_example 0.10 · placeholder 0.10 · prod_config 0.90 |
| 2 | 73 | Code critical | [#2 SQL injection](https://github.com/acme/app/security/code-scanning/2) | `src/api/users.py:30` | 🔴 fix now (80%) | true_pos 0.90 · reachable 0.90 · test_code 0.10 · exploitability 0.83 |
| 3 | 64 | Dep high | [#3 lodash: Prototype pollution](https://github.com/x/y/security/dependabot/3) | `package-lock.json` | 🔴 upgrade now (80%) | dev_only 0.10 · vuln_used 0.90 · urgency 0.83 |
| 4 | 3 | Code high | [#1 SQL injection](https://github.com/acme/app/security/code-scanning/1) | `tests/test_utils.py:30` | ⚪ review → dismiss (80%) | true_pos 0.20 · reachable 0.20 · test_code 0.90 · exploitability 0.17 |

## jev vs laya

| Metric | Value |
|---|---|
| Same recommendation | 4/4 (100%) |
| Mean priority gap | 0.0 points |
| Median latency | jev: 4 ms · laya: 4 ms |

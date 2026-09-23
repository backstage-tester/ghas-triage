# ghas-triage

Ranks a repo's open GitHub Advanced Security alerts (code scanning, secret scanning and Dependabot) with a fast decision model. For each alert it asks a handful of closed questions and turns the answers into a priority score plus a recommendation: **fix now**, **fix later**, or **review → dismiss**.

You can switch between two backends that use the same `POST /v1/systemone` API:

| Backend | What it is | Configure |
|---|---|---|
| `jev` | TypeSafe's hosted Jev | `TYPESAFE_API_KEY` (optionally `JEV_BASE_URL`) |
| `laya` | Laya, the open-source model that works like Jev, running on your own server | `LAYA_BASE_URL` (default `http://localhost:8100`), optional `LAYA_API_KEY` |

## Run it

```bash
pip install -r requirements.txt
cp .env.example .env && $EDITOR .env && set -a && . ./.env && set +a

python -m ghas_triage --repo acme/app                     # uses TRIAGE_BACKEND (default jev)
python -m ghas_triage --repo acme/app --backend laya      # switch backends
python -m ghas_triage --repo acme/app --backend jev,laya  # run both and add a comparison
```

This writes `triage.md` (a ranked table) and `triage.json` (the raw answers, latencies and token usage). Inside GitHub Actions, the markdown also appears as the job summary.

### Running Laya locally

Any server that exposes the TypeSafe API works. Example using [laya2typesafeapi](https://github.com/yunhai-dev/laya2typesafeapi):

```bash
git clone https://github.com/yunhai-dev/laya2typesafeapi && cd laya2typesafeapi
cp .env.example .env && docker compose up -d --build     # serves on :8100
curl localhost:8100/healthz
```

## What the model sees

| Alert | State sent | Questions |
|---|---|---|
| Code scanning | rule, severity, message, ±20 lines around the flagged code | true positive? reachable from untrusted input? test code? exploitability (0–3)? action |
| Secret scanning | secret type, validity, file, ±8 lines of context with the **secret replaced by `<REDACTED>`** | test/example? placeholder? prod/CI config? action |
| Dependabot | package, manifest, scope, advisory, CVSS/EPSS, patched version | dev-only? vulnerable code path commonly used? urgency (0–3)? action |

To tune the wording, edit `ghas_triage/questions.py`. The scoring formulas are in `score()` in `triage.py`.

**Safety properties:** the tool only reads. It never dismisses alerts or changes anything. The raw secret value is removed as soon as it's fetched and never goes to the model, the report, or the JSON file (the tests check this). If one alert fails, the run continues and the report shows that alert as an error.

## GitHub Actions

`.github/workflows/ghas-triage.yml` runs every Monday and can also be started by hand, with a choice of `jev`, `laya` or `jev,laya`.

- **Secrets:** `GHAS_READ_TOKEN` (a fine-grained PAT or GitHub App token with read access to *Code scanning alerts, Secret scanning alerts, Dependabot alerts, Contents*), `TYPESAFE_API_KEY`, and optionally `LAYA_API_KEY`
- **Variables:** `LAYA_BASE_URL`, and optionally `TRIAGE_BACKEND`
- **Laya in CI:** the runner has to be able to reach your Laya server. Use a self-hosted runner if Laya runs on your machine or LAN.

## Tests

```bash
pip install pytest && python -m pytest -q
```

The tests use a fake GitHub plus two fake model servers. One answers in TypeSafe's response format and the other in the grouped `nouls/choices/scores` format that some Laya servers use, so switching backends is tested end to end.

## Caveats

- Scores are advisory. Before trusting "review → dismiss", compare it against a sample of alerts you've already dismissed.
- Jev and Laya are text-only and have a 32k-token context. Snippets are capped at 6,000 characters.
- Question wording affects the answers a lot. Run `--backend jev,laya` after any edit to see how the two models react.

"""Decision backends. Jev (TypeSafe cloud) and Laya (self-hosted) speak the same
`POST /v1/systemone` contract, so a backend is just a base URL + key + model."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import requests

# name -> (base-url env var, default base URL, api-key env var)
BACKENDS: dict[str, tuple[str, str, str]] = {
    "jev": ("JEV_BASE_URL", "https://api.typesafe.ai", "TYPESAFE_API_KEY"),
    "laya": ("LAYA_BASE_URL", "http://localhost:8100", "LAYA_API_KEY"),
}


@dataclass
class Decision:
    answers: dict
    model: str | None
    latency_ms: float
    backend: str
    usage: dict = field(default_factory=dict)


class BackendError(RuntimeError):
    pass


class FatalBackendError(BackendError):
    """Non-retryable (4xx other than 429, or unparseable response)."""


class DecisionBackend:
    def __init__(self, name: str, base_url: str, api_key: str | None = None,
                 model: str = "jev-latest", timeout: float = 30.0, retries: int = 3):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        self.session.headers["Content-Type"] = "application/json"
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    def ask(self, state, questions: dict) -> Decision:
        payload = {"state": state, "model": self.model, "questions": questions}
        url = f"{self.base_url}/v1/systemone"
        last_err: Exception | None = None
        for attempt in range(self.retries):
            start = time.perf_counter()
            try:
                r = self.session.post(url, json=payload, timeout=self.timeout)
                latency = (time.perf_counter() - start) * 1000
                if r.status_code == 429 or r.status_code >= 500:
                    raise BackendError(f"{self.name}: HTTP {r.status_code}")
                if r.status_code >= 400:  # bad request / auth: retrying won't help
                    raise FatalBackendError(f"{self.name}: HTTP {r.status_code}: {r.text[:300]}")
                data = r.json()
                return Decision(answers=normalize_answers(data), model=data.get("model"),
                                latency_ms=latency, backend=self.name, usage=data.get("usage", {}))
            except FatalBackendError:
                raise
            except (requests.RequestException, ValueError, BackendError) as e:
                last_err = e
                if attempt < self.retries - 1:
                    time.sleep(min(2 ** attempt, 8))
        raise BackendError(f"{self.name} failed after {self.retries} attempts: {last_err}")


def normalize_answers(data: dict) -> dict:
    """TypeSafe returns {"answers": {...}}; some Laya servers group answers as
    {"nouls": {...}, "choices": {...}, "scores": {...}}. Return one flat dict."""
    if isinstance(data.get("answers"), dict):
        return data["answers"]
    flat: dict = {}
    for group, qtype in (("nouls", "noul"), ("choices", "choice"), ("scores", "score")):
        for qid, ans in (data.get(group) or {}).items():
            if not isinstance(ans, dict):  # bare value, e.g. "nouls": {"x": 0.9}
                ans = {qtype: ans}
            flat[qid] = {"type": qtype, **ans}
    if not flat:
        raise FatalBackendError(f"Unrecognized response shape: keys={list(data)}")
    return flat


def get_backend(name: str | None = None) -> DecisionBackend:
    name = (name or os.getenv("TRIAGE_BACKEND", "jev")).strip().lower()
    if name not in BACKENDS:
        raise ValueError(f"Unknown backend {name!r}; choose from {', '.join(BACKENDS)}")
    url_env, default_url, key_env = BACKENDS[name]
    return DecisionBackend(
        name=name,
        base_url=os.getenv(url_env, default_url),
        api_key=os.getenv(key_env),
        model=os.getenv("TRIAGE_MODEL", "jev-latest"),
        timeout=float(os.getenv("TRIAGE_TIMEOUT", "30")),
    )

"""Closed questions sent to Jev/Laya, one set per alert type.
Edit wording here to tune triage; the scoring in triage.py reads these ids."""

CODE_SCANNING = {
    "true_positive": {
        "type": "noul",
        "instructions": "Given the rule description and the code snippet (flagged lines marked with '>'), "
                        "is this finding a real vulnerability rather than a false positive?",
        "criteria": {
            "true": "The flagged pattern is genuinely vulnerable in this code",
            "false": "False positive: input is sanitized or constant, code is dead, or the pattern is misidentified",
        },
    },
    "untrusted_input": {
        "type": "noul",
        "instructions": "Can data from an untrusted source (HTTP request, user input, uploaded file, "
                        "external message, environment an attacker controls) reach the flagged code?",
        "criteria": {"true": "Untrusted input plausibly reaches it", "false": "Only trusted or constant data reaches it"},
    },
    "test_code": {
        "type": "noul",
        "instructions": "Is the flagged file test, example, fixture, benchmark, or build tooling code "
                        "that does not ship to production?",
        "criteria": {"true": "Non-production code", "false": "Production code"},
    },
    "exploitability": {
        "type": "score",
        "instructions": "How easy would it be for an external attacker to exploit this finding?",
        "criteria": ["Not exploitable", "Hard to exploit", "Exploitable with effort", "Easily exploitable"],
    },
    "action": {
        "type": "choice",
        "instructions": "What should the security team do with this alert?",
        "criteria": {
            "fix_now": "Real and exposed; fix this sprint",
            "fix_later": "Real but low exposure; schedule a fix",
            "review_dismiss": "Likely false positive or non-production; a human should review and dismiss",
        },
    },
}

SECRET_SCANNING = {
    "test_or_example": {
        "type": "noul",
        "instructions": "Is the secret located in test, example, documentation, or fixture files?",
        "criteria": {"true": "Test/example/docs location", "false": "Real application or config location"},
    },
    "placeholder": {
        "type": "noul",
        "instructions": "The secret value is redacted as <REDACTED>. Does the surrounding context suggest "
                        "it is a placeholder, dummy, or sample credential rather than a real one?",
        "criteria": {"true": "Likely a placeholder or sample", "false": "Likely a real credential"},
    },
    "production_config": {
        "type": "noul",
        "instructions": "Is the secret in production code, deployment configuration, infrastructure-as-code, "
                        "or CI/CD configuration?",
        "criteria": {"true": "Production/deploy/CI location", "false": "Not a production location"},
    },
    "action": {
        "type": "choice",
        "instructions": "What should the security team do with this exposed secret?",
        "criteria": {
            "rotate_now": "Treat as real and live: revoke/rotate immediately",
            "investigate": "Unclear: confirm with the owner whether it is real",
            "review_dismiss": "Likely placeholder or test value; review and dismiss",
        },
    },
}

DEPENDABOT = {
    "dev_only": {
        "type": "noul",
        "instructions": "Based on the manifest path and dependency scope, is this dependency used only for "
                        "development, testing, or build tooling (not shipped at runtime)?",
        "criteria": {"true": "Dev/test/build-only", "false": "Shipped at runtime"},
    },
    "vuln_path_likely_used": {
        "type": "noul",
        "instructions": "Would the vulnerable functionality described in the advisory likely be exercised "
                        "by a typical application that depends on this package?",
        "criteria": {"true": "Commonly used functionality", "false": "Niche or rarely used functionality"},
    },
    "urgency": {
        "type": "score",
        "instructions": "How urgent is upgrading this dependency?",
        "criteria": ["Can wait", "Next maintenance window", "This sprint", "Immediately"],
    },
    "action": {
        "type": "choice",
        "instructions": "What should the team do with this dependency alert?",
        "criteria": {
            "upgrade_now": "Upgrade or patch immediately",
            "upgrade_later": "Schedule the upgrade",
            "review_dismiss": "Low risk in context (dev-only or unused path); review and dismiss",
        },
    },
}

BY_KIND = {"code": CODE_SCANNING, "secret": SECRET_SCANNING, "dependabot": DEPENDABOT}

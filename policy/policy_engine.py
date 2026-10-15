import json
from pathlib import Path


TRUST_EVALUATION_FILE = (
    Path.home()
    / "zero-trust-5g"
    / "trust"
    / "trust_evaluation.json"
)


def load_trust_evaluation():
    with TRUST_EVALUATION_FILE.open("r") as f:
        return json.load(f)


def make_policy_decision(evaluation):
    signals = evaluation.get("signals", {})

    authentication_failures = signals.get(
        "authentication_failure_events", 0
    )

    if authentication_failures > 0:
        decision = "restrict"
        reason = "Authentication failure detected"
    else:
        decision = "retain"
        reason = "No authentication failure detected"

    return {
        "decision": decision,
        "reason": reason,
        "authentication_failure_events": authentication_failures,
    }


if __name__ == "__main__":
    evaluation = load_trust_evaluation()
    result = make_policy_decision(evaluation)

    print(json.dumps(result, indent=2))

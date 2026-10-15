import json
import re
from pathlib import Path

CONTEXT_FILE = (
    Path.home()
    / "zero-trust-5g"
    / "context"
    / "context_data.json"
)

OUTPUT_FILE = (
    Path.home()
    / "zero-trust-5g"
    / "trust"
    / "trust_evaluation.json"
)


def load_context():
    with CONTEXT_FILE.open("r") as f:
        return json.load(f)


def classify_event(event_text):
    text = re.sub(r"\x1b\[[0-9;]*m", "", event_text).lower()

    if "authentication failure" in text or "authentication failure(m" in text:
        return "authentication_failure"

    if "registration complete" in text:
        return "registration"

    if "release sm context" in text or "removed session" in text:
        return "session_release"

    if "sm-contexts" in text and "modify" in text:
        return "session_activity"

    if "mobile reachable timer expired" in text:
        return "reachability_timer_expired"

    if "dnn[" in text:
        return "network_context"

    return "other"


def evaluate_context(context):
    events = context.get("events", [])

    signals = {
        "registration_events": 0,
        "authentication_failure_events": 0,
        "session_activity_events": 0,
        "session_release_events": 0,
        "reachability_timer_events": 0,
        "network_context_events": 0,
        "unique_ue_ips": set(),
        "unique_dnn": set(),
        "unique_sst": set(),
    }

    evaluated_events = []

    authentication_failure_keys = set()

    for event in events:
        event_type = classify_event(event.get("event", ""))

        if event_type == "registration":
            signals["registration_events"] += 1

        elif event_type == "authentication_failure":
            failure_key = (
                event.get("source"),
                event.get("timestamp"),
            )

            if failure_key not in authentication_failure_keys:
                authentication_failure_keys.add(failure_key)
                signals["authentication_failure_events"] += 1

        elif event_type == "session_activity":
            signals["session_activity_events"] += 1

        elif event_type == "session_release":
            signals["session_release_events"] += 1

        elif event_type == "reachability_timer_expired":
            signals["reachability_timer_events"] += 1

        elif event_type == "network_context":
            signals["network_context_events"] += 1

        if event.get("ue_ip"):
            signals["unique_ue_ips"].add(event["ue_ip"])

        if event.get("dnn"):
            signals["unique_dnn"].add(event["dnn"])

        if event.get("sst") is not None:
            signals["unique_sst"].add(event["sst"])

        evaluated_events.append({
            "timestamp": event.get("timestamp"),
            "source": event.get("source"),
            "ue_supi": event.get("ue_supi"),
            "event_type": event_type,
            "ue_ip": event.get("ue_ip"),
            "dnn": event.get("dnn"),
            "sst": event.get("sst"),
        })

    signals["unique_ue_ips"] = sorted(signals["unique_ue_ips"])
    signals["unique_dnn"] = sorted(signals["unique_dnn"])
    signals["unique_sst"] = sorted(signals["unique_sst"])

    return {
        "context_event_count": len(events),
        "signals": signals,
        "evaluated_events": evaluated_events,
    }


if __name__ == "__main__":
    context = load_context()
    result = evaluate_context(context)

    with OUTPUT_FILE.open("w") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))
    print(f"\nEvaluation saved to: {OUTPUT_FILE}")

import re
import json
from datetime import datetime
from pathlib import Path

LOG_DIR = Path("/var/log/open5gs")

LOG_FILES = [
    "amf.log",
    "smf.log",
    "upf.log",
]

UE_PATTERN = re.compile(r"\[?(imsi-\d+)\]?")
IP_PATTERN = re.compile(r"IPv4\[(\d+\.\d+\.\d+\.\d+)\]")
DNN_PATTERN = re.compile(r"DNN\[(.*?)\]")
SST_PATTERN = re.compile(r"S_NSSAI\[SST:(\d+)")
TIME_PATTERN = re.compile(
    r"(\d{2}/\d{2} \d{2}:\d{2}:\d+\.\d+)"
)


def parse_log_file(path):
    events = []

    if not path.exists():
        return events

    with path.open("r", errors="replace") as log:
        for line in log:
            if "imsi-" not in line and "authentication failure" not in line.lower():
                continue

            event = {
                "source": path.stem,
                "timestamp": None,
                "ue_supi": None,
                "ue_ip": None,
                "dnn": None,
                "sst": None,
                "event": line.strip(),
            }

            time_match = TIME_PATTERN.search(line)
            if time_match:
                event["timestamp"] = time_match.group(1)

            ue_match = UE_PATTERN.search(line)
            if ue_match:
                event["ue_supi"] = ue_match.group(1)

            ip_match = IP_PATTERN.search(line)
            if ip_match:
                event["ue_ip"] = ip_match.group(1)

            dnn_match = DNN_PATTERN.search(line)
            if dnn_match:
                event["dnn"] = dnn_match.group(1)

            sst_match = SST_PATTERN.search(line)
            if sst_match:
                event["sst"] = int(sst_match.group(1))

            events.append(event)

    return events


def collect_context():
    events = []

    for filename in LOG_FILES:
        events.extend(parse_log_file(LOG_DIR / filename))

    events.sort(key=lambda x: x["timestamp"] or "")

    return {
        "collection_time": datetime.now().isoformat(),
        "event_count": len(events),
        "events": events,
    }


if __name__ == "__main__":
    context = collect_context()

    output_file = Path.home() / "zero-trust-5g" / "context" / "context_data.json"

    with output_file.open("w") as f:
        json.dump(context, f, indent=2)

    print(json.dumps(context, indent=2))
    print(f"\nContext saved to: {output_file}")

import json
import subprocess
from pathlib import Path

POLICY_ENGINE = "/root/zero-trust-5g/policy/policy_engine.py"

OUTPUT_FILE = Path.home() / "zero-trust-5g" / "enforcement" / "enforcement_result.json"

PEP_CHAIN = "ZERO_TRUST_PEP"

def load_policy_result():
    output = subprocess.check_output(["python3", POLICY_ENGINE], text=True)
    return json.loads(output)

def apply_pep(decision):
    subprocess.run(["iptables", "-F", PEP_CHAIN], check=True)
    target = "ACCEPT" if decision == "retain" else "DROP"
    subprocess.run(["iptables", "-A", PEP_CHAIN, "-j", target], check=True)

def enforce_policy(policy_result):
    decision = policy_result.get("decision")

    if decision == "retain":
        action = "allow"
        status = "access_retained"
    elif decision == "restrict":
        action = "restrict"
        status = "access_restricted"
    elif decision == "revoke":
        action = "deny"
        status = "access_revoked"
    else:
        action = "deny"
        status = "unknown_policy_decision"

    apply_pep(decision)

    return {
        "policy_decision": decision,
        "enforcement_action": action,
        "status": status,
        "pep_chain": PEP_CHAIN,
        "pep_action": "ACCEPT" if decision == "retain" else "DROP",
    }

if __name__ == "__main__":
    policy_result = load_policy_result()
    result = enforce_policy(policy_result)

    with OUTPUT_FILE.open("w") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))
    print(f"\nEnforcement result saved to: {OUTPUT_FILE}")

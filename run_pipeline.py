import subprocess


TRUST_ENGINE = (
    "/root/zero-trust-5g/trust/trust_engine.py"
)

POLICY_ENGINE = (
    "/root/zero-trust-5g/policy/policy_engine.py"
)

ENFORCEMENT_ENGINE = (
    "/root/zero-trust-5g/enforcement/enforcement_engine.py"
)


def run_stage(name, script):
    print(f"\n{'=' * 60}")
    print(f"{name}")
    print(f"{'=' * 60}")

    subprocess.run(
        ["python3", script],
        check=True
    )


if __name__ == "__main__":
    run_stage("TRUST EVALUATION", TRUST_ENGINE)
    run_stage("POLICY DECISION", POLICY_ENGINE)
    run_stage("POLICY ENFORCEMENT", ENFORCEMENT_ENGINE)

    print(f"\n{'=' * 60}")
    print("END-TO-END PIPELINE COMPLETED")
    print(f"{'=' * 60}")

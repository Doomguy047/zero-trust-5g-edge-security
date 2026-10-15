# Re-evaluating Trust in 5G Edge Environments: A Zero Trust Security Perspective

A proof-of-concept implementation that investigates Zero Trust-inspired context collection, event classification, policy decisions, and packet-filtering enforcement in a 5G test environment using Open5GS and UERANSIM.

## Overview

This project explores how authentication-related events and network context can inform access-restriction decisions in a 5G edge environment.

The implementation collects selected Open5GS logs, classifies relevant events, evaluates a simple policy, and applies the resulting decision through an iptables-based Policy Enforcement Point (PEP).

The project is a functional proof of concept. It demonstrates a rule-based enforcement workflow rather than a complete production Zero Trust Architecture.

## Research Objectives

- Collect network context from selected Open5GS AMF, SMF, and UPF logs.
- Classify observed events, including registration, authentication failures, session activity, session releases, reachability timers, and network-context events.
- Generate a policy decision from the observed authentication-failure count.
- Apply the decision through an existing iptables PEP chain.
- Compare connectivity in a control scenario and an authentication-failure scenario.

## Architecture

The implementation consists of five Python scripts:

| Component | Responsibility |
|---|---|
| `context/context_collector.py` | Collects selected events from Open5GS log files and writes the context dataset. |
| `trust/trust_engine.py` | Classifies events, aggregates event counts and context indicators, and produces a trust evaluation summary. |
| `policy/policy_engine.py` | Selects `restrict` when authentication failures are detected; otherwise selects `retain`. |
| `enforcement/enforcement_engine.py` | Executes the policy engine and applies the resulting decision through the existing `ZERO_TRUST_PEP` iptables chain. |
| `run_pipeline.py` | Runs the trust, policy, and enforcement stages in sequence. |

### Processing workflow

1. Open5GS generates network-function logs.
2. The context collector extracts relevant events into `context/context_data.json`.
3. The trust engine classifies and aggregates the collected events.
4. The policy engine determines whether access should be retained or restricted.
5. The enforcement engine updates the existing PEP chain to allow or drop forwarded traffic.

**Important:** `run_pipeline.py` does not run the context collector. The context dataset must already exist before the pipeline is executed.

## Experimental Environment

The implementation was tested in the following environment:

- **Operating system:** Kali Linux Rolling, ARM64
- **Virtualization:** UTM on an Apple Silicon Mac
- **5G core:** Open5GS v2.8.0-90-g941e4cc
- **UE and RAN simulator:** UERANSIM v3.3.0
- **Database:** MongoDB container
- **Data network:** `internet`
- **UE address in the tested setup:** `10.45.0.2`
- **User-plane gateway:** `10.45.0.1`

These are the parameters of the tested environment, not universal defaults for every Open5GS or UERANSIM installation.

## Experimental Results

Two scenarios were evaluated using preserved experiment outputs.

| Metric | Control scenario | Authentication-failure scenario |
|---|---:|---:|
| Context events | 48 | 58 |
| Authentication failures counted | 0 | 1 |
| Policy decision | `retain` | `restrict` |
| PEP action | `ACCEPT` | `DROP` |
| Ping packet loss | 0% | 100% |

In the control scenario, the policy retained access, the PEP allowed the traffic, and all three ping packets succeeded.

In the authentication-failure scenario, the collected dataset contained one deduplicated authentication-failure event. The policy selected restriction, and the PEP applied a `DROP` action. All three ping packets failed, and the PEP counter recorded three dropped packets totalling 252 bytes.

These results demonstrate the observed behavior in the tested setup. They do not establish performance under large-scale workloads or prove that every possible 5G attack can be detected.

## Requirements and Configuration

Before running the scripts, configure a working Open5GS and UERANSIM environment and ensure the relevant Open5GS logs are accessible.

The current scripts use paths under:

`/root/zero-trust-5g/`

If you run the project from a different directory or on another machine, update the hard-coded paths in the scripts accordingly.

The enforcement stage also expects the `ZERO_TRUST_PEP` iptables chain and the required forwarding-chain configuration to have been established. The scripts should not be assumed to create the complete firewall setup automatically.

Run the scripts with the permissions required to read the relevant logs and manage the firewall rules.

## Execution

Run the stages in the following order.

### 1. Collect context

From the project directory, execute:

```bash
sudo python3 context/context_collector.py
```

Confirm that the expected context dataset is generated at `context/context_data.json`.

### 2. Run the pipeline

```bash
sudo python3 run_pipeline.py
```

The pipeline runs the trust evaluation, policy decision, and enforcement stages. Review the generated trust evaluation and enforcement result files, and verify the relevant firewall counters.

**Operational caution:** The enforcement stage modifies firewall rules and may interrupt connectivity. Use an isolated, controlled test environment and inspect the current rules before running it.

The commands above assume the configured paths and script invocation are compatible with your local installation. Review those settings before execution on a different machine.

## Limitations

- Event classification is keyword-based and depends on the log formats and patterns handled by the scripts.
- The implementation aggregates event counts and context indicators; it does not calculate a numerical trust score.
- The policy is rule-based and currently focuses on the presence of authentication-failure events.
- Enforcement uses an existing iptables chain rather than a demonstrated native integration with the 5G Policy Control Function (PCF) or User Plane Function (UPF) policy interface.
- The experiments cover the two tested scenarios and do not constitute a comprehensive security evaluation.
- Throughput, latency, scalability, and performance under sustained traffic have not been established.

## Research Scope

This repository contains the implementation used to investigate a Zero Trust-inspired security workflow in a simulated 5G environment. The code and reported results should be interpreted within the scope of the documented implementation and experiments.

## License

See [`LICENSE`](LICENSE) for the terms governing use, modification, and distribution.
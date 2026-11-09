# Teminal-bench-V2

A curated set of **8 sample Terminal-Bench–style tasks** for evaluating AI coding agents in realistic terminal environments.

These tasks follow the [Terminal-Bench](https://www.tbench.ai/) / Harbor task shape: a containerized workspace, a human-written instruction, a reference solution (oracle), and sealed verifiers that score **final outcomes** rather than command traces. Difficulty comes from long-horizon exploration, interacting constraints, and domain reasoning—not from ambiguity or missing inputs.

---

## Author

| Field | Value |
| --- | --- |
| Author | [rjyothiprakash2003](https://github.com/rjyothiprakash2003) |
| GitHub | https://github.com/rjyothiprakash2003 |

Every task’s `task.toml` lists this same single author. No co-authors.

---

## What’s inside

| Metric | Value |
| --- | --- |
| Sample tasks | 8 |
| Difficulty | Hard (all) |
| Primary language | Go (+ Bash harness) |
| Domains | Build/deps, security, disaster recovery, scientific computing, machine learning |
| Typical expert estimate | ~3–8 hours per task |

Each sample task is self-contained: an agent lands in a Docker environment, reads the instruction and contract docs, implements or repairs the deliverable, and is graded by a **separate verifier** against sealed holdouts the agent never sees.

---

## Task layout

Every sample task directory uses the same Harbor / Terminal-Bench shape:

```text
<task-name>/
├── instruction.md      # Agent-facing prompt (what to build / repair)
├── task.toml           # Metadata, timeouts, network/CPU/memory, artifacts
├── environment/        # Docker image + staged /app contents
├── solution/           # Reference (oracle) solution
└── tests/              # Verifier, sealed fixtures, reward harness
```

### How grading works

1. **Agent phase** — The agent works in an isolated container (often with no network) under the timeouts in `task.toml`.
2. **Artifact handoff** — Declared artifacts (binaries, source trees, reports) are copied out of the agent environment.
3. **Verifier phase** — A separate container rebuilds and/or runs the submission against sealed corpora, compares byte-exact outputs / exit codes / dispositions, and emits a binary reward.
4. **Anti–reward-hack** — Holdout expects stay out of the agent-visible tree; many tasks rebuild from submitted sources under an unprivileged UID.

---

## Sample tasks

### Build & dependency management

| Task | Language | Summary |
| --- | --- | --- |
| [`apache-ant-build-integrity-checker`](./apache-ant-build-integrity-checker) | Go | Repair the Ember / Ant build gate (`forgegraph`, `propseal`, `evidenceledger`, `reportwire`) so release decisions honor integrity contracts, digests, cycles, and deterministic `ember_gate_decision.json` output. |
| [`dart-pub-dependency-conflict-analyzer`](./dart-pub-dependency-conflict-analyzer) | Go | Build offline `pubguard` to audit Dart/Flutter workspaces: pubspec discovery, constraint/source/cycle issues, lockfile mismatches, and byte-identical JSON reports. |

### Security

| Task | Language | Summary |
| --- | --- | --- |
| [`classify-network-behavior-profiles`](./classify-network-behavior-profiles) | Go | Fix SOC hunt admission (`huntgate`, `sigscore`, `peerhunt`, `triageprio`) so C2 beacon / spray / tunneling windows get correct CLEAN / WATCH / ALERT labels and deterministic threat reports. |
| [`shadow-authority-drift`](./shadow-authority-drift) | Go | Restore zero-trust federation IAM audit (`realmshadow`): AJN1 journal decode, trust-mesh replay, nineteen finding kinds, and compact `trust_mesh_audit.json` across sealed realm cases. |

### System administration

| Task | Language | Summary |
| --- | --- | --- |
| [`coordinate-enterprise-disaster-recovery`](./coordinate-enterprise-disaster-recovery) | Go | Repair DR orchestration (`drgate`, `wavesync`, `depgraph`, `slaedge`) for datacenter drill replay with RTO/RPO gates, wave capacity, rollback scope, and identical recovery reports. |

### Scientific computing

| Task | Language | Summary |
| --- | --- | --- |
| [`estimate-fluid-instability-thresholds`](./estimate-fluid-instability-thresholds) | Go | Fix Kelvin–Helmholtz shear admission (`flowgate`, `shearfv`, `growscan`, `massguard`): Richardson gates, growth schemes, CFL rules, and deterministic instability threshold reports. |

### Machine learning

| Task | Language | Summary |
| --- | --- | --- |
| [`optimize-active-learning-sampling`](./optimize-active-learning-sampling) | Go | Repair active-learning query selection (`samplegate`, `pickcore`, `stratops`, `effimath`) for uncertainty / diversity / hybrid strategies under a fixed labeling budget. |
| [`validate-distributed-service-dependencies`](./validate-distributed-service-dependencies) | Go | Calibrate soft vs hard feature detectors for STABLE / REVIEW / OUTLIER classification with evidence stacking, cycle/coupling findings, and byte-identical pairing-class reports. |

---

## Language & domain breakdown

```text
Go ........ all 8 sample tasks (Bash for test / solution harnesses)

Build ..... apache-ant-build-integrity-checker,
            dart-pub-dependency-conflict-analyzer

Security .. classify-network-behavior-profiles,
            shadow-authority-drift

Ops ....... coordinate-enterprise-disaster-recovery

Science ... estimate-fluid-instability-thresholds

ML ........ optimize-active-learning-sampling,
            validate-distributed-service-dependencies
```

---

## Working with a sample task

Each task’s `instruction.md` is the agent brief. Contracts and policy JSON usually live under the staged environment once the image is built.

```bash
# Read the agent instruction
less <task>/instruction.md

# Inspect metadata (timeouts, difficulty, author)
less <task>/task.toml

# Peek at the oracle entrypoint
ls <task>/solution

# Peek at verifier / tests
ls <task>/tests
```

Running tasks end-to-end requires a Harbor / Terminal-Bench–compatible harness and the task Docker environments. Prefer the official [Harbor](https://github.com/harbor-framework/terminal-bench) tooling and the [tbench.ai](https://www.tbench.ai/) docs for oracle and agent trials.

---

## Design principles reflected in these sample tasks

- **Contract-first** — Behavior is defined by integrity / admission / replay contracts, not by guessing from examples.
- **Byte-exact acceptance** — Successful reports use compact JSON, stable sort keys, and a trailing newline so reruns match exactly.
- **Sealed holdouts** — Graded inputs are absent from the agent-visible tree; matching only the shipped fixtures is not enough.
- **Separate verifier** — Agent and grader containers are isolated to reduce reward hacking.
- **Realistic failure modes** — Build tampering, C2 triage miss-labels, DR rollback scope, shear-threshold edge cases, IAM freeze≠quarantine≠seal, and active-learning budget traps.

---

## Repository map

```text
.
├── README.md
├── apache-ant-build-integrity-checker/
├── classify-network-behavior-profiles/
├── coordinate-enterprise-disaster-recovery/
├── dart-pub-dependency-conflict-analyzer/
├── estimate-fluid-instability-thresholds/
├── optimize-active-learning-sampling/
├── shadow-authority-drift/
└── validate-distributed-service-dependencies/
```

---

## References

- [Terminal-Bench 3.0 announcement](https://www.tbench.ai/news/terminal-bench-3-0)
- [Terminal-Bench project site](https://www.tbench.ai/)
- [Harbor / Terminal-Bench harness](https://github.com/harbor-framework/terminal-bench)
- [Terminal-Bench authoring overview](https://deaimer.github.io/tb-docs/tracks/terminal-bench)

---

## License & attribution

All sample tasks in this repository are authored by **[rjyothiprakash2003](https://github.com/rjyothiprakash2003)**. Task metadata, instructions, environments, solutions, and verifiers are packaged for agent evaluation. Consult upstream Terminal-Bench / Harbor licensing before redistributing commercially.

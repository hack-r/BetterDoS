# BetterDoS Modernization Plan

Date: 2026-03-10

## 1. Purpose And Reframe

This repository currently centers on offensive stress methods in a single, monolithic script. The modernization objective is to transform it into a **controlled, reproducible cybersecurity research platform** for use in:

- Isolated lab networks
- Synthetic targets and digital twins
- Authorized red-team simulation environments

The platform must not be used against real, unauthorized systems.

## 2. Current-State Review (From Repo)

Observed in this codebase:

- Core logic is monolithic in `start.py` (~1.8k+ lines, mixed concerns).
- CLI parsing, orchestration, transport methods, proxy handling, and utility tooling are tightly coupled.
- Method implementations are thread-heavy and manually managed.
- No formal experiment model (no hypothesis, scenario metadata, run manifest, result schema).
- No repeatable benchmark harness for multi-method comparison.
- No explicit policy/guardrails layer that blocks non-lab targets.
- No test suite or CI quality gates for correctness/regression.

Repository references:

- `start.py`
- `README.md`
- `Dockerfile`
- `docker-compose.yml`
- `config.json`

## 3. Target-State Product Vision

Build a tool called (working name) `mh-research`:

- Experiment-first architecture (scenario -> execute -> observe -> analyze -> report)
- Plugin-based method system with strict interfaces
- Deterministic replay and provenance tracking
- One-command automated campaigns against simulated targets
- Evidence quality suitable for lab reports/papers

## 4. Safety, Ethics, And Lab Controls (Non-Negotiable)

Introduce hard guardrails before any test execution:

- Allowlist-only targets (CIDR/domain allowlist required)
- Mandatory `--lab-mode` and signed scenario manifests
- Runtime environment checks (deny public IP targets by default)
- Rate ceilings and fail-safe circuit breakers
- Immutable run audit log (who, what, where, when, config hash)
- Policy engine that rejects disallowed method-target combinations

Recommended policy defaults:

- Block internet-routable targets unless an explicit admin override key is present.
- Require explicit ownership/authorization metadata in every scenario.

## 5. Proposed Architecture

## 5.1 Package Layout

```text
src/mh_research/
  cli/
    main.py
    commands/
      run.py
      validate.py
      report.py
      replay.py
  core/
    config.py
    policy.py
    scheduler.py
    campaign.py
    telemetry.py
    results.py
    errors.py
  methods/
    base.py
    registry.py
    l4/
    l7/
  targets/
    simulators/
      webapp.py
      api_gateway.py
      game_server.py
      dns_service.py
    instrumentation/
      exporters.py
      traces.py
  analysis/
    scoring.py
    inference.py
    statistics.py
    visualization.py
  data/
    schemas/
      scenario.schema.json
      result.schema.json
      telemetry.schema.json
tests/
  unit/
  integration/
  e2e/
scenarios/
reports/
```

## 5.2 Core Interfaces

- `MethodPlugin`: capability metadata + `prepare()`, `execute_step()`, `teardown()`
- `TargetAdapter`: common control plane for simulated target lifecycle
- `TelemetrySink`: ingestion API for metrics/events/traces
- `PolicyGuard`: preflight and runtime enforcement checks
- `ExperimentRunner`: orchestrates factorial/iterative campaign execution

## 5.3 Data Contracts

Define JSON schemas for:

- Scenario definition (target model, test matrix, constraints)
- Run config (seed, concurrency envelope, duration profile)
- Results (per-step metrics + aggregate outcomes)
- Provenance metadata (git SHA, container digest, dependency lock)

## 6. One-Command Research Workflow

Desired command:

```bash
mh-research run scenarios/web_gateway_baseline.yaml
```

Command behavior:

1. Validate scenario schema and policy compliance.
2. Launch or connect to simulated target stack.
3. Generate campaign matrix (methods x load profiles x durations).
4. Execute scheduled trials with adaptive stopping rules.
5. Collect telemetry (latency, error modes, saturation points, resource pressure).
6. Infer probable weaknesses and confidence bounds.
7. Emit machine-readable artifacts and human report.

Artifacts per run:

- `artifacts/<run_id>/manifest.json`
- `artifacts/<run_id>/metrics.parquet`
- `artifacts/<run_id>/events.jsonl`
- `artifacts/<run_id>/analysis.md`
- `artifacts/<run_id>/report.html`

## 7. Research Methodology Upgrade

Replace ad-hoc stress loops with structured experimentation:

- Hypothesis-driven scenarios (expected failure modes)
- Controlled variables (method, intensity, target config)
- Randomized trial order and fixed seeds for reproducibility
- Multiple repetitions for statistical confidence
- Explicit stopping criteria (safety and significance)
- Comparative scoring across methods using normalized metrics

Potential scoring dimensions:

- Service degradation onset
- Error amplification slope
- Recovery half-time
- Resource exhaustion signature
- Detection evasion (for synthetic detectors only)

## 8. Migration Roadmap (Phased)

## Phase 0: Governance And Repositioning (Week 1)

Deliverables:

- Rename project narrative from attack tool to lab research harness.
- Add `ETHICS.md`, `LAB_SCOPE.md`, `POLICY.md`.
- Add target allowlist enforcement scaffold.
- Mark legacy CLI as deprecated and gated.

Exit criteria:

- No run executes without policy preflight.

## Phase 1: Structural Refactor (Weeks 2-3)

Deliverables:

- Split `start.py` into package modules.
- Introduce typed config models (Pydantic/dataclasses).
- Implement plugin registry for methods.
- Keep behavioral parity in a `legacy_compat` command.

Exit criteria:

- Existing capabilities runnable via modular architecture.

## Phase 2: Experiment Engine (Weeks 4-5)

Deliverables:

- Scenario schema and validator.
- Campaign scheduler and run-state machine.
- Telemetry pipeline with structured storage.

Exit criteria:

- Repeatable campaigns with deterministic IDs and manifests.

## Phase 3: Simulated Target Lab — REMOVED

> Simulated targets are provided by the Kapalan lab environment.
> No additional target provisioning work is needed in this repo.

## Phase 4: Analytics And Reporting (Weeks 6-7)

Deliverables:

- Statistical analysis package.
- Vulnerability hypothesis ranking with confidence intervals.
- Auto-generated markdown and HTML reports.

Exit criteria:

- One-command run produces publishable lab report artifacts.

## Phase 5: CI/CD And Quality Gates (Week 10)

Deliverables:

- Unit/integration/e2e test suites.
- Static analysis, type checks, security scans, dependency pinning.
- Reproducible container image and release workflow.

Exit criteria:

- Green CI required for merge and release.

## 9. Technical Debt Priorities (Immediate)

Highest priority refactors from `start.py`:

- Separate transport logic from CLI parsing.
- Replace global counters and mutable global state with run-scoped state.
- Replace manual thread spawning with orchestrated worker pools.
- Standardize logging and structured event emission.
- Normalize error handling (typed exceptions vs broad suppression).

## 10. Suggested Initial Backlog (First 20 Tickets)

1. Create `src/mh_research` package skeleton.
2. Add `pyproject.toml` with lint/type/test tooling.
3. Add scenario schema v0 and validator command.
4. Implement policy preflight (allowlist + private-network check).
5. Extract method metadata from legacy sets into registry.
6. Build `ExperimentRunner` minimal execution loop.
7. Add run manifest generation with hash of inputs.
8. Add structured logger output (`jsonl`).
9. Add telemetry sink interface.
10. Add Docker lab target: simple instrumented web service.
11. Add latency/error collector.
12. Add deterministic seed handling.
13. Add trial repetition and aggregation.
14. Add stop conditions and safety circuit breaker.
15. Add report renderer (Markdown).
16. Add report renderer (HTML).
17. Add baseline scenario examples.
18. Add migration compatibility command for legacy args.
19. Add CI pipeline (ruff, mypy, pytest).
20. Add contributor docs and ethics checklist.

## 11. Success Metrics

By modernization completion, the project should demonstrate:

- `<= 1` command to run a full lab campaign
- `100%` runs with manifest + reproducibility metadata
- `0` unauthorized-target executions (enforced by policy)
- Statistically comparable method evaluations across repeated trials
- Report generation time under 2 minutes after run completion

## 12. Risks And Mitigations

- Risk: legacy offensive framing persists.
  - Mitigation: enforce policy engine + documentation + defaults that block unsafe operation.
- Risk: method plugins diverge in behavior/quality.
  - Mitigation: conformance tests and plugin certification checks.
- Risk: telemetry overhead skews results.
  - Mitigation: sampled instrumentation and control runs.
- Risk: non-deterministic network effects in lab.
  - Mitigation: seeded scheduling and repeated trial statistics.

## 13. Next Implementation Step

Start with Phase 0 + Phase 1 foundations:

- Add governance docs and policy guard scaffold.
- Carve out minimal package structure.
- Preserve current behavior behind a compatibility adapter while building experiment-native CLI.

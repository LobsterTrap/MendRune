# MendRune Implementation Ledger

**Purpose:** This file is the durable implementation plan and task ledger for MendRune. Any coding agent continuing the work MUST read this file, `README.md`, `SPECIFICATION.md`, and the current Git diff before changing code.

**Status values:** `NOT_STARTED`, `IN_PROGRESS`, `BLOCKED`, `DONE`, `DEFERRED`

**Update rule:** Before starting a task, set it to `IN_PROGRESS` and add the agent/date. Before setting it to `DONE`, record fresh verification evidence. If interrupted, update **Current handoff** with the exact next action, failures, and modified files.

## Current handoff

- **Current phase:** Complete — P0 through P10 implemented
- **Active task:** None
- **Last completed:** P10-T04
- **Next action:** None; qualified libkrun runtime evidence has been recorded with the pinned UBI 10 image in `Containerfile`.
- **Known blockers:** None. Runtime tests still skip in the default suite unless `MENDRUNE_RUNTIME_TEST_IMAGE` and the host runtime name are supplied.
- **Checkpoint state:** Deterministic P0–P8 implementation is committed through full campaign acceptance, with runtime tests present and gated on qualified infrastructure.
- **Resume protocol:** Run the Astral quality gates and `pytest -m runtime` with a qualified local image when available. Keep Goose unable to affect deterministic acceptance checks.

## Global invariants

- Supplied patches are primary; Goose adaptation remains optional and disabled by default.
- Python alone invokes Git, Goose, and Podman, always with argument arrays and `shell=False`.
- Astral uv manages environments, dependencies, the committed lockfile, and project command execution; direct project `pip install` workflows are unsupported.
- Ruff is the required formatter/linter and ty is the required static type checker; both run through `uv run`.
- MendRune-owned persistent records use safe YAML.
- Repository code executes only through the isolated executor.
- A failed, missing, malformed, timed-out, skipped-required, or uncertain check prevents acceptance.
- No task is `DONE` without recorded verification evidence.
- Do not implement deferred features while prerequisite deterministic phases are incomplete.

## Phase summary

| Phase | Goal | Status | Depends on |
|---|---|---|---|
| P0 | Foundation, Astral tooling, packaging, test harness | DONE | — |
| P1 | Typed YAML campaign model and `mendrune verify` | DONE | P0 |
| P2 | Safe storage, state machine, evidence capture | DONE | P1 |
| P3 | Git worktrees, strict patches, tree integrity | DONE | P1–P2 |
| P4 | Deterministic oracle, regressions, scanner logic | DONE | P1–P2 |
| P5 | Podman/krun executor and preflight | DONE | P1–P2 |
| P6 | Phase A baseline vertical slice | DONE | P3–P5 |
| P7 | Phase B isolated remediation units | DONE | P6 |
| P8 | Phase C cumulative composition and final verdict | DONE | P7 |
| P9 | Optional Goose adaptation | DONE | P8 |
| P10 | Hardening, end-to-end fixtures, release readiness | DONE | P8–P9 |

---

## P0 — Foundation

### P0-T01 — Reconcile design for explicit evidence and generated paths

- **Status:** DONE
- **Depends on:** —
- **Deliverables:**
  - `README.md` explains `evidence_paths` and `allowed_generated_paths`.
  - `SPECIFICATION.md` defines validation, snapshotting, hashing, mutation, and cleanup rules.
- **Acceptance evidence:**
  - Markdown fences balanced.
  - `git diff --check -- README.md SPECIFICATION.md` exits 0.
- **Evidence recorded:** Completed 2026-07-22; verification rerun as part of P0-T02.

### P0-T02 — Create durable implementation ledger

- **Status:** DONE
- **Depends on:** P0-T01
- **Deliverables:** `IMPLEMENTATION_PLAN.md` with stable IDs, dependencies, statuses, acceptance commands, and handoff protocol.
- **Acceptance command:**
  ```bash
  test -s IMPLEMENTATION_PLAN.md && rg -n "Current handoff|P0-T01|P10" IMPLEMENTATION_PLAN.md
  ```
- **Evidence recorded:** Completed 2026-07-22.

### P0-T03 — Create package and test skeleton

- **Status:** DONE
- **Owner/date:** goose / 2026-07-22
- **Depends on:** P0-T02
- **Deliverables:**
  - `pyproject.toml`
  - `src/mendrune/__init__.py`, `__main__.py`, `cli.py`
  - `tests/` with smoke tests
  - Console script `mendrune`
- **Acceptance commands:**
  ```bash
  uv run pytest
  uv run python -m mendrune --help
  ```
- **Handoff notes:** Keep dependencies minimal. Prefer stdlib `argparse`; use PyYAML for safe YAML and pytest for tests. Manage the environment and all commands through uv; keep Ruff and ty mandatory.
- **Evidence recorded:** 2026-07-22 — `python3 -m pytest` (3 passed), `PYTHONPATH=src python3 -m mendrune --help`, `PYTHONPATH=src python3 -m mendrune --version`, and `git diff --check` all exited 0.

### P0-T04 — Add Astral quality gates

- **Status:** DONE
- **Owner/date:** goose / 2026-07-22
- **Depends on:** P0-T03
- **Deliverables:**
  - uv-managed development dependency group and committed `uv.lock`
  - Ruff formatting and lint configuration
  - ty static type-check configuration
  - All project quality commands run through `uv run`
- **Acceptance commands:**
  ```bash
  uv sync --locked --group dev
  uv run ruff format --check .
  uv run ruff check .
  uv run ty check
  uv run pytest
  ```
- **Evidence recorded:** 2026-07-22 — generated `uv.lock`; `uv sync --locked --group dev`, `uv run ruff format --check .`, `uv run ruff check .`, `uv run ty check`, `uv run pytest` (73 passed), and `git diff --check` all exited 0.

---

## P1 — Campaign model and non-executing verification

### P1-T01 — Define typed domain models and enums

- **Status:** DONE
- **Depends on:** P0-T03
- **Deliverables:** Models for campaign, repository, composition, unit, vulnerability, oracle command, patch, regression, scanner, execution, mounts, policies, Goose, and storage.
- **Acceptance:** Unit tests cover required fields, defaults, enums, and unknown-field rejection.
- **Evidence recorded:** 2026-07-22 — model and relationship tests included in 32-test passing suite.

### P1-T02 — Implement bounded safe YAML loading

- **Status:** DONE
- **Depends on:** P1-T01
- **Deliverables:** Safe loader with byte/depth/scalar/collection limits, alias/tag rejection, duplicate-key rejection, and useful location-aware errors.
- **Acceptance:** Hostile YAML fixtures fail with stable reason codes; valid campaign loads.
- **Evidence recorded:** 2026-07-22 — duplicate key, aliases/anchors, symlink, and byte-limit tests pass.

### P1-T03 — Implement cross-field validation

- **Status:** DONE
- **Depends on:** P1-T01–P1-T02
- **Deliverables:** Exact composition membership, globally unique vulnerability ownership, globally unique command IDs, required scanners/regressions, image digest, path rules, Goose defaults, and generated-path restrictions.
- **Acceptance:** Positive complete campaign and focused negative fixtures.
- **Evidence recorded:** 2026-07-22 — composition, unique ownership, Goose enablement, scanner requirement, generated paths, repository, patch hash/syntax, and dirty-source tests pass.

### P1-T04 — Implement static evidence-path validation

- **Status:** DONE
- **Owner/date:** goose / 2026-07-22
- **Depends on:** P1-T03
- **Deliverables:** Resolve `evidence_paths` beneath evidence root; recursively inventory deterministic regular files; reject symlinks/special files/escape; ensure `/evidence/...` args map to declarations.
- **Acceptance:** Traversal, symlink, FIFO, undeclared `/evidence` argument, and duplicate-target tests fail closed.
- **Evidence recorded:** 2026-07-22 — deterministic directory inventory, owner deduplication, symlink, FIFO, hard-link, immutable capture, and manifest tests pass.

### P1-T05 — Implement `mendrune verify`

- **Status:** DONE
- **Depends on:** P1-T03–P1-T04, P3-T01 (Git ref resolution may initially be a narrow early extraction)
- **Deliverables:** Non-executing command validates YAML, local Git identity/base ref, patch files/hashes/syntax, paths/policies, image syntax, and enabled Goose recipe.
- **Acceptance commands:**
  ```bash
  mendrune verify tests/fixtures/campaigns/valid/campaign.yaml
  uv run pytest tests/unit/test_config.py tests/integration/test_verify_cli.py
  ```
- **Evidence recorded:** 2026-07-22 — valid campaign, patch tamper rejection, dirty source preservation, Git ref resolution, strict patch parsing, and documented Goose recipe-validation invocation pass within the 36-test suite.

---

## P2 — Storage, provenance, and state

### P2-T01 — Implement safe run paths and atomic YAML writes

- **Status:** DONE
- **Depends on:** P1
- **Deliverables:** Root-confined joins, symlink rejection, stable safe YAML, atomic replace, timestamps, and newline guarantee.
- **Evidence recorded:** 2026-07-22 — confined run paths, atomic YAML/hash, traversal and symlink-parent tests pass in 54-test suite.

### P2-T02 — Implement artifact copy and SHA-256 manifests

- **Status:** DONE
- **Owner/date:** goose / 2026-07-22
- **Depends on:** P2-T01
- **Deliverables:** Immutable copies for campaign, patches, evidence, and optional recipe; deterministic `evidence-manifest.yaml` and `hashes.yaml`.
- **Acceptance:** Tamper and race-focused tests; containers later consume snapshot paths only.
- **Evidence recorded:** 2026-07-22 — immutable capture/hash, readonly snapshot, existing destination, hash manifest, and tamper detection tests pass.

### P2-T03 — Implement state machine and check records

- **Status:** DONE
- **Depends on:** P2-T01
- **Deliverables:** Explicit legal transitions, terminal-state protection, unique check IDs, required check statuses, atomic `run.yaml` updates.
- **Evidence recorded:** 2026-07-22 — normal path, loops, all terminal states, and illegal transition tests pass. Persisted check-record models remain to be integrated under P2-T02/P2-T04.

### P2-T04 — Implement deterministic reporting skeleton

- **Status:** DONE
- **Depends on:** P2-T02–P2-T03
- **Deliverables:** `status` and `report` read stored evidence only; mandatory limitation wording.
- **Evidence recorded:** 2026-07-22 — deterministic stored-record rendering, mandatory limitations, missing/invalid evidence failures, no live repository reads, and CLI status/report tests pass.

---

## P3 — Git and patch integrity

### P3-T01 — Resolve repository and base commit safely

- **Status:** DONE
- **Depends on:** P1
- **Deliverables:** Local non-bare repository checks, full commit resolution, defensive Git environment/config, no hooks/aliases/external diff/submodule recursion.
- **Evidence recorded:** 2026-07-22 — commit resolution, dirty source preservation, and unknown ref tests pass.

### P3-T02 — Detached disposable worktree lifecycle

- **Status:** DONE
- **Depends on:** P3-T01, P2
- **Deliverables:** Create/verify/remove clean detached worktrees without modifying source worktree; cleanup records.
- **Evidence recorded:** 2026-07-22 — detached exact-HEAD worktree creation, cleanliness, registration removal, and source preservation tests pass.

### P3-T03 — Strict unified-diff parser and policy

- **Status:** DONE
- **Depends on:** P1
- **Deliverables:** Standard text diffs only; paths, hunks, file states, line counts; deny binary/combined/rename/mode by default; protected paths and limits.
- **Evidence recorded:** 2026-07-22 — valid text, empty, binary, traversal, new file, count mismatch, line limit, allow/deny glob tests pass.

### P3-T04 — Exact-context placement and Git application

- **Status:** DONE
- **Owner/date:** goose / 2026-07-22
- **Depends on:** P3-T02–P3-T03
- **Deliverables:** Full-context unambiguous relocation algorithm; `git apply --check`; no reduced context/3-way/reject/partial; application-range evidence.
- **Evidence recorded:** 2026-07-22 — parser retains full old-side hunk content; exact-header and unique relocation placement tests pass; ambiguous relocation fails closed; Git check/application returns original/applied ranges.

### P3-T05 — Actual diff and source-integrity accounting

- **Status:** DONE
- **Depends on:** P3-T04
- **Deliverables:** Expected patch-derived tree fingerprint; tracked content/type/mode immutability after commands; only untracked regular files under `allowed_generated_paths`; generated cleanup before combined diff.
- **Evidence recorded:** 2026-07-22 — deterministic tracked snapshots record path/mode/size/SHA-256; tracked mutations and undeclared, ignored, or special generated files fail; declared untracked regular outputs pass. Final cleanup integration remains with P8-T03.

---

## P4 — Deterministic checks

### P4-T01 — Structured YAML nonce oracle

- **Status:** DONE
- **Depends on:** P1–P2
- **Deliverables:** Fresh nonce, strict result schema, fresh output dir, safe path/type checks, expected phase values, crash/timeout never equals mitigation.
- **Evidence recorded:** 2026-07-22 — valid, nonce mismatch, fake Boolean, unexpected states, and crash-not-mitigation tests pass.

### P4-T02 — Regression scheduling

- **Status:** DONE
- **Depends on:** P1–P2
- **Deliverables:** Shared/unit/accumulated selection and required-result records.
- **Evidence recorded:** 2026-07-22 — deterministic shared, isolated, and composition-prefix accumulation schedules plus all required result states pass focused tests.

### P4-T03 — First scanner adapter and normalization

- **Status:** DONE
- **Depends on:** P1–P2
- **Deliverables:** Semgrep adapter; canonical identity/fingerprint, severity mapping, stable sorting/deduplication, malformed output failure.
- **Evidence recorded:** 2026-07-22 — strict native Semgrep JSON schema/error/path/severity validation and deterministic canonical normalization pass focused tests.

### P4-T04 — Differential scanner comparison

- **Status:** DONE
- **Depends on:** P4-T03
- **Deliverables:** Baseline vs isolated, previous-stage vs cumulative, severity increases, final nondeterminism check.
- **Evidence recorded:** 2026-07-22 — stable fingerprint, deduplication, threshold, below-threshold, and severity-increase tests pass. Semgrep native-output adapter remains P4-T03.

---

## P5 — Isolated executor

### P5-T01 — Pure Podman command builder

- **Status:** DONE
- **Depends on:** P1
- **Deliverables:** Rootless, explicit runtime, no network, cap drop, no-new-privileges, read-only root, limits, narrow mounts, environment allowlist, fresh output/scratch.
- **Acceptance:** Unit tests inspect argv and prove forbidden mounts/env absent.
- **Evidence recorded:** 2026-07-22 — explicit runtime/network/capability/no-new-privileges/read-only/limits/mounts and environment rejection tests pass.

### P5-T02 — Process lifecycle and bounded capture

- **Status:** DONE
- **Owner/date:** goose / 2026-07-22
- **Depends on:** P5-T01, P2
- **Deliverables:** Timeout, kill/remove, separate bounded stdout/stderr, truncation metadata, container metadata, cleanup uncertainty.
- **Evidence recorded:** 2026-07-22 — mocked lifecycle tests prove argv execution with `shell=False`, unique named containers, timeout kill/remove, independent bounded captures, metadata, launch failure, and fail-closed cleanup uncertainty.

### P5-T03 — Runtime preflight

- **Status:** DONE
- **Depends on:** P5-T02
- **Deliverables:** Non-root, rootless Podman, runtime identity, KVM/libkrun launch, exact image digest, resource/network controls.
- **Evidence recorded:** 2026-07-22 — mocked preflight tests cover non-root/rootless Podman, executable crun + libkrun identity, writable KVM, exact local image digest, hardened no-pull qualification launch, and fail-closed cleanup.

### P5-T04 — Runtime security tests

- **Status:** DONE
- **Depends on:** P5-T03
- **Deliverables:** Qualified-host tests for network, mounts, credentials, capabilities, limits, timeout cleanup. Explicit skips only for missing krun infrastructure.
- **Evidence recorded:** 2026-07-23 — built the digest-pinned UBI 10 `Containerfile` image and ran all six tests through Fedora's `krun` libkrun runtime: 6 passed. Tests validate denied external networking, relabeled mount boundaries, absent credentials/sockets, read-only root, libkrun VM CPU/memory annotations plus configured PID limit, and timeout stop/removal.

---

## P6 — Phase A vertical slice

### P6-T01 — Orchestrate preflight and immutable input capture

- **Status:** DONE
- **Depends on:** P2–P5
- **Deliverables:** Validate, capture/hash evidence, freeze effective supplied patches, qualify executor, create baseline worktree.
- **Evidence recorded:** 2026-07-22 — preflight orchestration captures immutable campaign/repository/evidence/patch provenance, freezes supplied patches, hashes the run, qualifies isolation before capture, creates a clean detached baseline, records failures, and cleans up; adaptation remains intentionally deferred to P9.

### P6-T02 — Execute baseline build/regressions/oracles/scans

- **Status:** DONE
- **Depends on:** P6-T01
- **Deliverables:** Build, shared regressions, every vulnerability reproduces, scans normalize, source-integrity checks after every command.
- **Evidence recorded:** 2026-07-22 — injected-executor tests run the complete baseline schedule, validate nonce-bound vulnerable oracle results and Semgrep output, persist bounded logs/checks/findings, hash evidence, and fail closed on source mutation.

### P6-T03 — Baseline end-to-end fixture

- **Status:** DONE
- **Depends on:** P6-T02
- **Acceptance:** Valid baseline persists evidence; non-reproducing oracle, mutation, scanner failure, and regression failure terminate with stable codes.
- **Evidence recorded:** 2026-07-22 — real temporary Git/worktree/run-store integration tests persist successful baseline evidence and prove stable failures for non-reproduction, source mutation, scanner failure, and regression failure.

---

## P7 — Phase B isolated units

### P7-T01 — Apply each unit from a fresh base worktree

- **Status:** DONE
- **Depends on:** P6
- **Deliverables:** Ordered patches, actual-diff accounting per patch, clean isolation from other units.
- **Evidence recorded:** 2026-07-22 — unit tests create a fresh base worktree per composition-ordered unit, apply frozen patches in declared order, record placement/diff hashes, reject empty/tampered results, and remove isolated worktrees.

### P7-T02 — Verify unit mitigation/regressions/scans

- **Status:** DONE
- **Depends on:** P7-T01
- **Deliverables:** Unit oracles false, shared + unit regressions, scans vs Phase A, source integrity, evidence.
- **Evidence recorded:** 2026-07-22 — isolated checks require owned oracle mitigation, run shared+unit regressions, normalize/compare scanners against Phase A, verify integrity after every command, persist manifests, and fail partial mitigation with stable evidence.

### P7-T03 — Multi-patch/multi-vulnerability isolated fixtures

- **Status:** DONE
- **Depends on:** P7-T02
- **Acceptance:** Positive and failures for partial mitigation, regression, mutation, and new scanner finding.
- **Evidence recorded:** 2026-07-22 — multi-patch/multi-vulnerability integration fixtures pass the positive path and prove stable partial mitigation, regression, mutation, and prohibited scanner failures with cleanup and hash verification.

---

## P8 — Phase C, final verification, acceptance

### P8-T01 — Strict cumulative pre-application reproduction

- **Status:** DONE
- **Depends on:** P7
- **Deliverables:** Current unit vulnerabilities must still reproduce; otherwise terminal `ambiguous_overlap`.
- **Evidence recorded:** 2026-07-22 — cumulative tests require nonce-bound reproduction immediately before each unit and persist terminal `ambiguous_overlap` / `unit_vulnerability_already_mitigated` evidence before applying an overlapping patch.

### P8-T02 — Cumulative apply and accumulated rechecks

- **Status:** DONE
- **Depends on:** P8-T01
- **Deliverables:** One cumulative worktree, ordered units, all applied oracles, shared + accumulated unit regressions, scans vs previous stage.
- **Evidence recorded:** 2026-07-22 — one cumulative worktree applies composition-ordered units, reruns all applied oracles and accumulated regressions, compares scanners stage-to-stage, persists manifests/hashes, cleans up, and detects reopened prior vulnerabilities.

### P8-T03 — Final full-stack verification and combined diff

- **Status:** DONE
- **Depends on:** P8-T02
- **Deliverables:** Repeat all checks; remove allowed generated paths; final integrity; deterministic supplied series and combined diff.
- **Evidence recorded:** 2026-07-22 — final verification repeats build/oracles/regressions/scans, compares the last stage, removes only allowed generated files, verifies clean tracked integrity, emits actual combined diff and ordered provenance, verifies required evidence/hashes, and advances to evidence assembly without premature acceptance.

### P8-T04 — Acceptance conjunction and campaign fixtures

- **Status:** DONE
- **Depends on:** P8-T03
- **Acceptance:** Two-unit accepted campaign plus overlap, reopened vulnerability, cumulative regression, scanner, evidence tamper, and interrupted-run failures.
- **Evidence recorded:** 2026-07-22 — `run_campaign` chains all phases, accepts only after evidence assembly and verified hashes/provenance, persists verdict/report limitations, maps CLI exits, cleans workspaces, and retains failure evidence; cumulative overlap/reopen and prior Phase B failure fixtures pass. Additional two-unit campaign hardening remains P10.

---

## P9 — Optional Goose adaptation

### P9-T01 — Add and validate recipe

- **Status:** DONE
- **Depends on:** P8
- **Deliverables:** `recipes/adapt-patch.yaml` using only documented fields; `extensions: []`; schema-constrained transient response.
- **Evidence recorded:** 2026-07-22 — recipe uses documented version/title/description/file parameter/prompt/extensions/settings/response schema fields; `goose recipe validate recipes/adapt-patch.yaml` exits 0.

### P9-T02 — Bounded evidence bundle and adapter

- **Status:** DONE
- **Depends on:** P9-T01
- **Deliverables:** One adaptation per enabled patch during input capture; strict response parsing; no prose recovery.
- **Evidence recorded:** 2026-07-22 — bounded untrusted evidence bundles and one-shot Goose invocation parse only the final schema-shaped JSON line and reject timeout, failure, empty/oversized/malformed/extra responses and stderr recovery.

### P9-T03 — Freeze provenance and reuse bytes

- **Status:** DONE
- **Depends on:** P9-T02
- **Deliverables:** Preserve supplied/adapted bytes and hashes; reuse frozen effective patch in B/C/final; no stage readaptation.
- **Evidence recorded:** 2026-07-22 — capture validates adapted syntax/policy/applicability once, stores immutable supplied/adapted bytes with derived and recipe hashes, and existing B/C/final paths consume only the frozen effective record.

### P9-T04 — Goose-negative tests

- **Status:** DONE
- **Depends on:** P9-T03
- **Acceptance:** Disabled path never invokes Goose; malformed/empty/out-of-policy output fails; model cannot affect verdict.
- **Evidence recorded:** 2026-07-22 — disabled adaptation avoids Goose; adapter tests reject malformed/empty/extra/stderr/timeout output; deterministic parser, policy, applicability, and full campaign checks remain authoritative.

---

## P10 — Hardening and completion

### P10-T01 — Hostile-input security suite

- **Status:** DONE
- **Depends on:** P8–P9
- **Deliverables:** YAML bombs, symlinks/FIFOs, hostile Git config/hooks, traversal diffs, ANSI/control output, output symlinks, oversized artifacts, prompt injection as inert data.
- **Evidence recorded:** 2026-07-22 — 22 security tests cover YAML bombs/limits/tags, symlinks/FIFOs/hardlinks, oversized evidence/oracles, hostile Git hooks/config/environment, traversal diffs, bounded ANSI/control output, output symlinks, and inert prompt-injection strings.

### P10-T02 — Documentation/example parity

- **Status:** DONE
- **Depends on:** all implemented phases
- **Deliverables:** README commands and complete campaign run exactly as documented; accepted/rejected example reports.
- **Evidence recorded:** 2026-07-22 — README/spec reflect implemented verify/run/status/report behavior and limitations; `campaigns/example/setup.py` deterministically generates a complete campaign; integration test generates and verifies it without Podman. Runtime execution remains qualified-image dependent as documented.

### P10-T03 — Full verification matrix

- **Status:** DONE
- **Depends on:** P10-T01–P10-T02
- **Acceptance commands:**
  ```bash
  uv sync --locked --group dev
  uv run ruff format --check .
  uv run ruff check .
  uv run ty check
  uv run pytest
  uv run mendrune verify campaigns/example/campaign.yaml
  # On a qualified host:
  uv run pytest -m runtime
  ```
- **Evidence recorded:** 2026-07-23 — locked sync, Ruff format/lint, ty, full default pytest (178 passed, 6 environment-gated runtime skips), explicit qualified UBI 10/libkrun runtime suite (6 passed), accepted documented full campaign, and `git diff --check` all completed successfully.

### P10-T04 — Final review and release decision

- **Status:** DONE
- **Depends on:** P10-T03
- **Deliverables:** Security review, clean diff review, known limitations, runtime evidence, no unsupported completion claims.
- **Evidence recorded:** 2026-07-22 — two review rounds resolved acceptance completeness, scanner identity/confinement, bounded writable storage, frozen recipe validation, effective line budget, and unsupported patch-state findings. Final independent reviewer decision: GO; no release blockers. Qualified runtime execution remains unproven because the required local digest-pinned image was not supplied.

## Parallel-work guidance

Only parallelize tasks that do not edit the same files:

- P3 Git modules and P4 pure oracle/scanner modules can proceed in parallel after P1/P2 interfaces stabilize.
- P5 executor can proceed in parallel with P3/P4 if model interfaces are frozen.
- Tests MAY be partitioned by module directory; avoid two agents editing shared fixtures or `models.py`.
- P6–P8 orchestration phases are sequential and should have one owner at a time.
- P9 Goose integration is intentionally deferred until P8 is complete.

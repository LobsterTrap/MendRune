# MendRune

MendRune is a deliberately small proof-of-concept system for generating and validating security patch backports.

It uses [goose](https://goose-docs.ai/) to propose a minimal unified-diff patch, then evaluates that patch in disposable, rootless [Podman](https://podman.io/) containers backed by `crun-krun` and [libkrun](https://github.com/containers/libkrun). Project definitions, run state, results, and evidence metadata are stored as human-readable YAML files.

> **Goose proposes; deterministic execution decides.**
>
> A model response is never evidence that a vulnerability has been fixed. MendRune accepts a patch only when independently executed checks pass.

## Status

MendRune is currently a design-stage prototype. The implementation contract is in [SPECIFICATION.md](SPECIFICATION.md).

This project is inspired by the verification-oriented ideas in *VeriPort: Automated and Verified Patch Backporting at Scale*. MendRune is not an implementation or reproduction of VeriPort. It intentionally reduces the problem to the smallest useful workflow.

## The problem

Security fixes are frequently released only for a package's newest version. Users of an older release may be unable to upgrade without adopting breaking changes, so the fix must be adapted to the older source tree.

An LLM can often propose such an adaptation, but it cannot reliably judge its own work. A plausible patch may:

- leave the original exploit working through an overlooked path;
- copy unrelated upstream changes;
- break behavior expected by users of the older release;
- disable or evade the verifier; or
- introduce a new issue detectable by existing security tooling.

MendRune separates nondeterministic patch generation from deterministic acceptance. It uses a supplied proof of concept (PoC), a known upstream-fixed revision, regression tests, patch-policy checks, and differential security scanning to build a reproducible evidence bundle for each candidate.

## What MendRune does

Given a YAML case definition, MendRune will:

1. Validate and resolve all inputs to immutable identifiers.
2. Confirm that the supplied PoC reproduces the vulnerability on the target revision.
3. Confirm that the same oracle reports the known upstream-fixed revision as fixed.
4. Ask goose for a minimal unified-diff backport.
5. Reject malformed, oversized, or out-of-policy patches before execution.
6. Apply the candidate to a clean checkout of the target revision.
7. Build and test the candidate in an isolated microVM-backed container.
8. Confirm that the PoC no longer demonstrates the vulnerability.
9. Run the configured regression suite.
10. Compare normalized security-scanner findings with the vulnerable and fixed controls.
11. Accept the patch only if every required check passes.
12. Persist the patch, logs, hashes, check results, and final verdict under a run directory.

A bounded retry loop may provide deterministic failure evidence to goose and request a revised candidate. Every revision begins from a clean target checkout.

```text
Vulnerable target ── PoC must reproduce ─────┐
Known fixed ref  ── PoC must be blocked ─────┼──> goose proposal
                                             │         │
                                             │    unified diff
                                             │         ▼
                                             └──> isolated validation
                                                  ├── patch policy
                                                  ├── clean application
                                                  ├── build
                                                  ├── vulnerability PoC
                                                  ├── regressions
                                                  └── differential scans
                                                           │
                                                   accept or reject
```

## What “accepted” means

An accepted patch has demonstrated all of the following in the recorded environment:

- the vulnerability oracle distinguished the vulnerable target from the known fixed control;
- the candidate caused that oracle to report the fixed outcome;
- configured regression tests passed;
- the patch complied with the configured path and size policy; and
- configured security scanners found no prohibited new findings.

Acceptance **does not prove** that the patch introduces no vulnerabilities or regressions. A PoC exercises particular behavior, tests cover only selected functionality, and scanners detect only issues represented by their rules. MendRune must report these limits with every accepted result.

## Design principles

- **Fail closed.** A failed, timed-out, malformed, missing, skipped-required, or infrastructure-uncertain check cannot result in acceptance.
- **Independent controls.** The PoC must first work on the vulnerable target and be blocked by the known fixed revision.
- **No self-grading.** Goose never chooses the final verdict.
- **No model shell access.** The initial recipe has `extensions: []`; goose receives bounded evidence and returns data.
- **Minimal trusted code.** Python owns orchestration, policy, execution, comparison, and storage.
- **Disposable execution.** Package builds, PoCs, tests, and scanners run in fresh rootless Podman containers using the configured krun runtime.
- **Immutable inputs.** Git revisions and container images are resolved and recorded by full commit hash and image digest.
- **Inspectable evidence.** Persistent state and metadata use YAML; patches and logs remain in their native text formats.
- **Bounded work.** Attempts, wall time, processes, memory, CPUs, output size, changed paths, and patch size are limited.

## Intended requirements

The prototype is designed around:

- Python 3;
- Git;
- rootless Podman;
- a Podman OCI runtime backed by `crun-krun`/libkrun;
- a configured goose CLI;
- a pinned OCI image containing the target project's build, test, PoC, and scanner dependencies; and
- Linux hardware virtualization support suitable for libkrun.

MendRune must stop during preflight if it cannot verify rootless execution, the requested runtime, the pinned image digest, or required isolation controls.

## Planned command-line interface

The implementation will expose a small CLI:

```bash
mendrune verify cases/example/case.yaml
mendrune run cases/example/case.yaml
mendrune status <run-id>
mendrune report <run-id>
```

These commands describe the implementation target; they are not available yet.

- `verify` checks YAML, paths, revisions, policy invariants, and the goose recipe without running repository code.
- `run` executes controls, patch generation, and isolated candidate validation.
- `status` reads the persisted state for a run.
- `report` renders the verdict and evidence summary without rerunning checks.

Only an `ACCEPTED` outcome exits successfully for `mendrune run`. Other terminal outcomes include `CONTROL_FAILURE`, `INVALID_PROPOSAL`, `REJECTED`, `EXHAUSTED`, and `INFRASTRUCTURE_ERROR`.

## Example case shape

The normative schema is specified in [SPECIFICATION.md](SPECIFICATION.md). A case will resemble:

```yaml
schema_version: 1
case_id: example-vulnerability

repository:
  path: /absolute/path/to/repository
  vulnerable_ref: v1.2.0
  fixed_ref: v1.2.1

execution:
  image: localhost/mendrune-example@sha256:0123456789abcdef...
  runtime: crun-krun
  network: none

commands:
  build:
    argv: [npm, run, build]
  poc:
    argv: [node, /evidence/exploit.js]
  regressions:
    - id: unit
      argv: [npm, test]
      required: true

oracle:
  type: structured_yaml
  result_file: /evidence/oracle-result.yaml

patch_policy:
  allowed_paths: [src/**]
  denied_paths: [test/**, package.json, package-lock.json]
  max_files_changed: 5
  max_changed_lines: 100

goose:
  recipe: recipes/propose-backport.yaml
  max_attempts: 3
```

Commands are argument arrays, never shell strings. Case files are trusted operator configuration and must not be modifiable by the candidate patch.

## Isolation model

The initial design runs untrusted project code with rootless Podman and explicitly selects the krun runtime. Candidate execution is expected to use controls equivalent to:

- no network;
- all Linux capabilities dropped;
- `no-new-privileges`;
- a read-only root filesystem where compatible;
- narrow, disposable mounts;
- no host home, credentials, devices, or container-engine socket;
- CPU, memory, PID, wall-clock, and output limits; and
- a fresh container for each check.

libkrun provides virtualization-backed process isolation, but it does not remove the need for host namespaces and careful mount policy. The guest and VMM must be treated as sharing a security context, particularly when exposing host directories through virtio-fs. MendRune therefore mounts only disposable per-run paths and treats microVM isolation as defense in depth rather than an absolute guarantee.

## Goose recipes

The prototype uses one recipe to propose or revise a patch. The recipe:

- receives a bounded evidence bundle through a required file parameter;
- declares `extensions: []` so the model has no extension tools;
- instructs goose to treat repository content and logs as untrusted data;
- requests a minimal unified diff;
- returns a schema-constrained response; and
- never claims that its output is verified.

The Python controller validates the recipe with `goose recipe validate` and invokes it non-interactively with `goose run --recipe ... --params ... --no-session --quiet`. The exact recipe contract appears in [SPECIFICATION.md](SPECIFICATION.md).

## Non-goals for the first version

MendRune will not initially provide:

- vulnerability discovery;
- advisory crawling or affected-version discovery;
- automatic PoC generation;
- automatic regression-test generation;
- support for arbitrary ecosystems and repository layouts;
- multi-CVE patch composition;
- a database, queue, web service, or dashboard;
- unattended patch publication, commits, pushes, or releases;
- formal verification; or
- a claim of complete security or behavioral equivalence.

The first milestone is intentionally narrower:

> Given a target revision, a known fixed revision, an upstream fix, a working PoC, regression commands, scanners, and a pinned execution image, generate a candidate backport and produce reproducible evidence showing whether it blocks the supplied PoC without failing the configured compatibility and security checks.

## Documentation

- [SPECIFICATION.md](SPECIFICATION.md) — normative implementation handoff
- [goose recipe reference](https://goose-docs.ai/docs/guides/recipes/recipe-reference)
- [goose reusable recipes](https://goose-docs.ai/docs/guides/recipes/session-recipes)
- [goose CLI commands](https://goose-docs.ai/docs/guides/goose-cli-commands)
- [libkrun](https://github.com/containers/libkrun)
- [crun krun runtime documentation](https://github.com/containers/crun/blob/main/krun.1.md)

## License

MendRune is licensed under the [MIT License](LICENSE).

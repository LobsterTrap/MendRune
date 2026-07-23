# MendRune

MendRune verifies Git-based security remediation campaigns.

You supply one local Git repository, one immutable vulnerable base commit, ordered remediation units, and immutable unified-diff patches. MendRune verifies each unit alone and then composes the full patch stack in disposable, rootless [Podman](https://podman.io/) containers backed by `crun-krun` and [libkrun](https://github.com/containers/libkrun). Configuration, state, normalized results, and evidence metadata remain inspectable YAML files.

> **Patches are supplied; deterministic execution decides.**
>
> Goose may optionally adapt a supplied patch when explicitly enabled, but it never decides acceptance.

## Status

MendRune provides the `verify`, `run`, `status`, and `report` commands. `verify` is a host-side, non-executing configuration check and does not require Podman. `run` executes repository code and requires a qualified rootless Podman host with the configured `crun-krun`/libkrun runtime and an image whose digest matches the campaign. Runtime acceptance is supported only in that qualified environment; generating or verifying the example does not establish runtime acceptance.

## Why campaigns?

Security maintenance often requires several fixes that interact. A patch can pass alone yet conflict with another patch, silently subsume it, or reopen a vulnerability fixed earlier in the stack. Validating only the final tree hides those failures.

A MendRune campaign therefore starts from exactly one local Git repository and one full, immutable vulnerable base commit. It verifies multiple ordered remediation units both independently and cumulatively. Each unit contains one or more vulnerabilities and one or more supplied patches; in v1, every vulnerability belongs to exactly one unit.

No known-fixed Git revision is required. MendRune does not accept archives.

## Verification workflow

```text
immutable vulnerable base commit
             │
             ├── Phase A: baseline
             │   ├── build
             │   ├── shared regressions
             │   ├── every vulnerability must reproduce
             │   └── required scans
             │
             ├── Phase B: isolated units (fresh base worktree per unit)
             │   └── patches in order → build → unit oracles mitigated
             │       → shared + unit regressions → scans
             │
             └── Phase C: cumulative composition (one fresh base worktree)
                 └── for each unit in composition.order:
                     reproduce that unit's vulnerabilities immediately before apply
                     → apply patches → build
                     → rerun all applied vulnerability oracles
                     → shared + accumulated unit regressions
                     → scans compared with previous accepted stage
```

Phase C's pre-application check is intentionally strict. If a unit's vulnerability is already mitigated, v1 fails with ambiguous overlap. There is no skip or apply-anyway mode. After each application, MendRune reruns all vulnerability oracles and regressions accumulated so far, which detects a later patch reopening an earlier vulnerability.

A campaign is accepted only when Phase A, every Phase B unit, every Phase C stage, the final full-stack checks, and all evidence/hash checks pass.

## Patch contract

Patches are primary operator-supplied inputs and are immutable. For v1, MendRune accepts standard text unified diffs and applies them in declared order without reduced-context matching, three-way fallback, reject files, or partial application. Relocation is permitted only when every original context line matches exactly, and the resulting location is recorded. Binary patches, renames, and mode changes are denied by default.

Each application uses:

- a clean, detached Git worktree at the recorded full base commit;
- disabled repository hooks;
- `git apply --check` before `git apply`;
- inspection of the actual Git diff after application and after every untrusted command;
- a read-only source mount where the project permits it, or explicit rejection of undeclared source-tree mutations; and
- accounting that rejects unexplained or out-of-policy changes.

The accepted result preserves the supplied patch series and emits a deterministic final combined diff from the base commit to the verified final worktree.

### Optional Goose adaptation

Goose patch adaptation is disabled by default. When an operator enables it for a patch, Goose receives a bounded evidence file and may return an adapted unified diff. MendRune preserves both files, labels the supplied patch as the origin and the adapted patch as a derived candidate, and records hashes and provenance. Adaptation never overwrites a supplied patch and never weakens deterministic checks.

The recipe is limited to verified Goose recipe capabilities: `version`, `title`, `description`, a required file parameter, `prompt`, `extensions: []`, `settings.temperature`, `settings.max_turns`, and `response.json_schema`.

The controller validates and invokes recipes with:

```bash
goose recipe validate recipes/adapt-patch.yaml
goose run --recipe recipes/adapt-patch.yaml \
  --params evidence_bundle=/absolute/path/to/evidence-bundle.md \
  --no-session --quiet
```

## Runnable example

The checked-in generator creates a tiny local Git repository, evidence programs, a patch, and a complete `campaign.yaml`. It records the generated base commit and patch SHA-256 automatically, avoiding a nested Git repository in this source tree.

```bash
uv sync --locked --group dev
uv run python campaigns/example/setup.py
uv run mendrune verify campaigns/example/generated/campaign.yaml
```

`verify` reads configuration and local Git metadata only; it does not invoke Podman or execute repository code. A successful result ends with output similar to:

```text
verified campaign documented-example at base commit <40-character-commit>
```

The generator uses a syntactically valid all-zero placeholder image digest by default because `verify` checks syntax, not local image availability. That placeholder does **not** qualify the campaign for `run`. To prepare the generated configuration for a qualified runtime, provide the exact digest of an image already available to that environment:

```bash
MENDRUNE_EXAMPLE_IMAGE_DIGEST='sha256:<64-lowercase-hex-digits>' \
  uv run python campaigns/example/setup.py
```

The checked-in `Containerfile` builds the test image from a digest-pinned Red Hat Universal Base Image 10 base. Build it rootlessly, inspect its resulting manifest digest, and configure the actual libkrun runtime executable installed by the host (`krun` on Fedora):

```bash
podman build --pull=never --format=oci \
  -t localhost/mendrune-example:runtime-v1 -f Containerfile .
IMAGE_DIGEST="$(podman image inspect localhost/mendrune-example:runtime-v1 --format '{{.Digest}}')"
MENDRUNE_EXAMPLE_IMAGE_DIGEST="$IMAGE_DIGEST" uv run python campaigns/example/setup.py
# Set execution.runtime to the host's libkrun-enabled runtime name when it is not crun-krun.
```

Then run only on a host that satisfies the rootless Podman and libkrun preflight:

```bash
uv run mendrune run campaigns/example/generated/campaign.yaml
```

Do not interpret successful generation or `verify` output as runtime acceptance. See [SPECIFICATION.md](SPECIFICATION.md) for the complete schema and runtime requirements.

## Safe vulnerability oracles

Each vulnerability uses an operator-supplied oracle. A PoC cannot prove mitigation merely by crashing or omitting output. The controller supplies a fresh cryptographic nonce, and the PoC must atomically write bounded structured YAML containing that exact nonce and a Boolean `vulnerable` result. Missing, stale, malformed, nonzero, or timed-out results fail closed.

## Isolation and storage

Untrusted builds, PoCs, tests, and scanners run in fresh containers through rootless Podman with the explicitly selected `crun-krun`/libkrun runtime. The intended controls include no network, dropped capabilities, `no-new-privileges`, narrow disposable mounts, no credentials or container-engine socket, and bounded CPU, memory, processes, time, and output.

libkrun is defense in depth, not an absolute boundary. Host directories exposed through virtio-fs still require careful namespace and mount policy.

Every oracle, regression, and scanner command explicitly declares the external files or directories it needs through `evidence_paths`. MendRune recursively inventories regular files, rejects symlinks and special files, copies the declared inputs into an immutable run snapshot, and hashes them before execution. Containers read that snapshot rather than the live campaign directory; undeclared external dependencies are unsupported.

Tracked source files must remain equal to the expected patch-derived state after every untrusted command. Builds may create untracked output only beneath explicit `execution.allowed_generated_paths` globs. The list defaults to empty, cannot overlap protected or patched paths, and is removed before the final combined diff is generated. Unexpected untracked files or any tracked-file mutation fail closed.

MendRune-owned persistent data uses YAML. Patches and logs retain their native text formats. JSON may be transient only when an external interface, such as Goose's schema-constrained response or a scanner, requires it.

## Development tooling

MendRune standardizes on the [Astral](https://astral.sh/) Python toolchain:

- **uv** manages the Python environment, dependency lockfile, installation, and command execution.
- **Ruff** provides formatting and linting.
- **ty** provides static type checking.

Contributors and coding agents should install uv and run project commands through it rather than invoking a project virtual environment or `pip` directly. uv installs and executes the locked Ruff, ty, and pytest versions declared by the project:

```bash
uv sync --group dev
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest
```

`uv.lock` is a required, version-controlled reproducibility artifact. CI and release verification must use the locked dependency graph.

## Command-line interface

```bash
mendrune verify <campaign.yaml>
mendrune run <campaign.yaml>
mendrune --runs-root <directory> status <run-id>
mendrune --runs-root <directory> report <run-id>
```

- `verify` checks campaign YAML, paths, Git identities, patch hashes and syntax, policies, evidence declarations, and optional Goose recipes without executing repository code or requiring Podman.
- `run` performs the campaign and requires the qualified container runtime and exact configured image digest.
- `status` reads persisted run state from `--runs-root` (default: `runs`).
- `report` renders recorded evidence from `--runs-root` without rerunning checks.

The configuration-checking subcommand is `verify`, not `validate`.

## Core principles

- **Fail closed.** Missing, malformed, failed, timed-out, skipped-required, or uncertain checks prevent acceptance.
- **Git-native and immutable.** One repository, one full base commit, immutable supplied patches, clean detached worktrees.
- **No self-grading.** Goose cannot accept a patch or campaign.
- **Composition is explicit.** v1 uses `composition.order`, not a dependency graph.
- **Recheck history.** Every cumulative stage retests all vulnerabilities and regressions applied so far.
- **Python orchestrates.** Python alone invokes Git, Goose, and Podman and writes state.
- **YAML first.** Human-readable flat files are the persistent system of record.
- **Evidence is reproducible.** Inputs, provenance, checks, logs, hashes, patch series, and final combined diff are retained.
- **Claims stay truthful.** Acceptance cannot prove the absence of all vulnerabilities or regressions.

## Non-goals for v1

- vulnerability discovery or PoC generation;
- archive input or export workflows;
- a required known-fixed revision;
- automatic patch generation;
- dependency-graph scheduling;
- overlap skip/apply-anyway modes;
- automatic commits, pushes, pull requests, or releases;
- a database, service, queue, or dashboard; or
- formal proof of security or behavioral equivalence.

## Documentation

- [SPECIFICATION.md](SPECIFICATION.md) — normative implementation handoff
- [goose recipe reference](https://goose-docs.ai/docs/guides/recipes/recipe-reference)
- [goose reusable recipes](https://goose-docs.ai/docs/guides/recipes/session-recipes)
- [goose CLI commands](https://goose-docs.ai/docs/guides/goose-cli-commands)
- [libkrun](https://github.com/containers/libkrun)
- [crun krun runtime documentation](https://github.com/containers/crun/blob/main/krun.1.md)

## License

MendRune is licensed under the [MIT License](LICENSE).

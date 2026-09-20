# scheck

A read-only security posture checker for one macOS or Linux host, locally or over
SSH. Every target command comes from a compiled catalog and runs through the same
policy, redaction and audit path. scheck never applies hardening changes.

**Current build:** collects facts, assesses them with compiled-in posture rules, grades
findings through operator context, and — without `--stop-after` — hands the facts to a
model that may run further catalog checks through the same policy and report findings
that scheck grades. A rule reads one fact, so exit 0 and an empty findings list mean no
rule fired — not that the host is secure; read the `assessments` coverage and the
skipped checks. **The model's quality has not been evaluated yet** (see
[docs/eval/phase2-results.md](docs/eval/phase2-results.md)); treat model findings as
evidence-backed candidates. This project is unreleased; interfaces may change before
the first GitHub release.

## Installation

Published binaries will be available from [GitHub Releases](https://github.com/b87/scheck/releases)
for Linux and macOS on amd64 and arm64. Until the first release is published, build
from source below. macOS assets use `darwin` in their name and are **unsigned and
unnotarized**.

Download the matching `scheck_VERSION_OS_ARCH.tar.gz` and `checksums.txt` into an
empty directory. Verify the downloaded archive before extracting:

```sh
sha256sum --ignore-missing -c checksums.txt       # Linux
shasum -a 256 --ignore-missing -c checksums.txt   # macOS
```

Confirm the matching archive reports `OK`, then run `tar -xzf ARCHIVE.tar.gz` and
`./scheck --version`. Install the binary into a directory on your PATH if desired.
On macOS, Gatekeeper may block downloaded unsigned binaries; after verifying the
download and deciding to trust it, use macOS System Settings → Privacy & Security
to allow the application. No Apple notarization is provided.

## Build from source and quick start

With the Go toolchain required by [go.mod](go.mod):

```sh
make build
bin/scheck local --stop-after facts --no-persist            # posture rules only, no model
bin/scheck ssh user@host --stop-after facts --no-persist
export OPENAI_API_KEY=...                                    # or --base-url for another endpoint
bin/scheck local --context hosts/gateway.yaml                # rules + the agentic pass (gpt-5.6-luna)
bin/scheck providers                                         # what is configured
bin/scheck config show                                       # effective settings with provenance
```

Operator context (`--context FILE|DIR|note:TEXT|target[:PATH]`, a `context:` block in
`scheck.yaml`, files under `.scheck/context/`) declares the host's role, exposure,
expected services and accepted risks; findings are graded through it with every
change attributed, and `scheck explain FINDING-ID --exposure internet` shows the
chain. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

SSH uses strict host-key verification and key/agent authentication. Checks needing
privileges are unavailable unless the session is root or authorized non-interactive
sudo is enabled with `--sudo`. scheck never asks for a password.

## AI agents and automation

```sh
bin/scheck local --stop-after facts --format json --no-persist
bin/scheck local --stop-after facts --format json --include-evidence --no-persist
bin/scheck catalog --platform linux --format json
bin/scheck explain sshd.config --format json
bin/scheck local --stop-after plan --format json
```

Read stdout, stderr and the exit code separately. Exit 1 means a posture rule found
something at or above the profile threshold; the report is still written. JSON declares
`run.assessment: "rules"` and carries `findings` plus an `assessments` entry per
selected rule (`matched`, `not_matched`, `not_applicable`, `not_assessed`); each fact
includes a one-line `summary`, its status and whether execution was attempted. A typed
fact's records are at `parsed.items`, with `parsed.partial` when the output was
incomplete. Optional evidence is redacted, bounded and extraction-filtered.
Use `--out report.json` to save the report. `--no-persist` disables the additional
state-directory artifact, not an explicit output file or audit log.

Use the repository-local [$scheck skill](.agents/skills/scheck/SKILL.md) to collect
and interpret evidence. It covers JSON discovery, exit codes, diagnostics, elevation
and partial results. For interactive inspection,
`-v` adds descriptions and `-vv` adds available redacted diagnostics.

## Project documentation

- [Specification](docs/SPEC.md): security boundaries and current/planned contracts.
- [Roadmap](docs/ROADMAP-0.0.1.md): implementation status and validation; M2 is built, its live evaluation is pending, M4 is next.
- [Configuration walkthrough](docs/CONFIGURATION.md): preferences, restrictions and context.
- [Phase 2 criteria](docs/eval/phase2-criteria.md) and [results](docs/eval/phase2-results.md): the frozen gate and its record.
- [Run report schema](docs/report-schema.json): implemented JSON report shape.
- [Contributor instructions](AGENTS.md): development workflow and required checks.
- [Release runbook](docs/RELEASING.md): GoReleaser, validation evidence and manual publication.

Run `make check` for vet, modernization, lint, the provider-dependency check and race
tests. Container integration tests use `make integ` and require Docker or Podman;
`make live` runs the opt-in tests that spend real money.

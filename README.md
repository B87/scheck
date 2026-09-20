# scheck

A read-only security posture checker for one macOS or Linux host, locally or over
SSH. Every target command comes from a compiled catalog and runs through the same
policy, redaction and audit path. scheck never applies hardening changes.

**Current build:** collects facts and produces readable or JSON reports. Automated
posture findings and the model-driven assessment are not implemented yet. Exit 0 and
an empty findings list do not mean the host is secure. This project is unreleased;
interfaces may change before the first GitHub release.

## Quick start

With the Go toolchain required by [go.mod](go.mod):

```sh
make build
bin/scheck local --stop-after facts --no-persist
bin/scheck ssh user@host --stop-after facts --no-persist
```

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

Read stdout, stderr and the exit code separately. JSON declares
`run.assessment: "none"`; each fact includes status and whether execution was
attempted. Optional evidence is redacted, bounded and extraction-filtered.
Use `--out report.json` to save the report. `--no-persist` disables the additional
state-directory artifact, not an explicit output file or audit log.

Use the repository-local [$scheck skill](.agents/skills/scheck/SKILL.md) to collect
and interpret evidence. It covers JSON discovery, exit codes, diagnostics, elevation
and partial results. For interactive inspection,
`-v` adds descriptions and `-vv` adds available redacted diagnostics.

## Project documentation

- [Specification](docs/SPEC.md): security boundaries and current/planned contracts.
- [Roadmap](docs/ROADMAP.md): implementation status and validation; M1.7 is next.
- [Run report schema](docs/report-schema.json): implemented JSON report shape.
- [Contributor instructions](AGENTS.md): development workflow and required checks.

Run `make check` for vet, modernization, lint and race tests. Container integration
tests use `make integ` and require Docker or Podman.

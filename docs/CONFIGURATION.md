# Configuring scheck — a walkthrough

scheck reads three kinds of input, and it helps to keep them apart:

| Kind | What it is | Where it lives | Can it widen what scheck does? |
|---|---|---|---|
| **Preferences** | which model, which profile, where runs are stored | user config, project `scheck.yaml`, flags | no |
| **Restrictions** | checks to skip, paths to deny, extra redactions | the same files; lists **accumulate** across them | no — every entry narrows |
| **Context** | what the host is for, what should be listening, which risks are accepted | `context:` block, `./.scheck/context/`, `--context` | no — it changes how findings are graded, never what runs |

Nothing in any file can add a command, widen a path or reveal a redacted value
(`SPEC.md` §9). Credentials are never read from a file: they come from the environment
(`OPENAI_API_KEY`) at run time.

`scheck config show` prints the effective result with the source of every value, and
`scheck config validate` applies the same rules a run applies. Both are local: neither
contacts a model or a target.

## 1. Personal defaults

The user config file is read first:

- Linux: `$XDG_CONFIG_HOME/scheck/config.yaml`, by default `~/.config/scheck/config.yaml`
- macOS: `~/Library/Application Support/scheck/config.yaml`

OpenAI's endpoint defaults to `gpt-5.6-luna`. Set `model:` (or `--model`) to pick
another family, or when `--base-url` is not OpenAI's.

```yaml
# ~/.config/scheck/config.yaml
model: gpt-5.6-terra
effort: high
state_dir: ~/.local/state/scheck
```

```
$ scheck config show
SETTING       VALUE                      SOURCE
provider      openai-compatible          default
model         gpt-5.6-terra              /home/me/.config/scheck/config.yaml
effort        high                       /home/me/.config/scheck/config.yaml
profile       baseline                   default
...
```

## 2. Team configuration

A project's `scheck.yaml` in the working directory is read second and overrides the
user file **per scalar key**; lists are unioned.

```yaml
# scheck.yaml (committed with the repository)
profile: hardened
elevate: sudo
disable_checks:
  - fs.suid            # a vendor image ships SUID helpers we have reviewed
deny_paths:
  - /etc/corp-secrets
redact_extra:
  - "internal\\.example\\.com"
targets:
  bastion: { host: 10.0.0.5, user: ops, identity: ~/.ssh/ops }
```

`config show` names every source of an accumulated entry rather than claiming one file
owns the merged list:

```
disable_checks (accumulated; every source that listed an entry is named)
  fs.suid        <- scheck.yaml
  net.listeners  <- /home/me/.config/scheck/config.yaml, scheck.yaml
```

## 3. Per-host context files

Context describes the host so findings are specific to its role. The structured block
(`SPEC.md` §6.2) is consumed by code, deterministically; everything else is prose the
model reads verbatim.

```yaml
# hosts/gateway.yaml
context:
  role: "public API gateway"
  exposure: internet            # internet | vpn | lan | airgapped
  environment: prod             # prod | staging | dev
  expected_services:
    - { port: 443, proto: tcp, purpose: "nginx public TLS", audience: internet }
    - { port: 5432, proto: tcp, purpose: "postgres", audience: vpc-only }
  accepted_risks:
    - { id: sshd.password_auth_enabled, reason: "break-glass path, MFA at bastion", expires: 2026-12-31 }
  owner: platform-team
```

```
$ scheck ssh bastion --context hosts/gateway.yaml --stop-after context
<operator_context>
...
## structured
exposure: internet
expected_services:
    - port: 443
...
</operator_context>
context: 1 source, 239 bytes of 32768 budget
  hosts/gateway.yaml  239 bytes  sha256 8f58364a1ab527a4…
```

Files under `./.scheck/context/` (`*.md`, `*.txt`, `*.yaml`) are read implicitly, in
lexical path order, after the config block and before `--context` flags. Nothing else
is read implicitly: name `ARCHITECTURE.md` or a runbook explicitly with `--context`.

A file **on the target** can describe the host (`--context target`, default
`/etc/scheck/context.md`). It is read through the same path policy as any other file,
appears in the audit log as the `text.cat` check, and is always prose: the machine
being audited cannot accept its own risks or declare its own exposure. `config show`
reports such a source as *unresolved*; it is read only during a run.

## 4. Inline notes and one-off overrides

```
$ scheck local --context "note:temporary build box, decommissioned next week" \
               --context hosts/gateway.yaml --profile baseline --stop-after facts
```

An explicit flag overrides both files and is attributed as `flag` in `config show`. A
flag left at its registered default never overrides a file, so `--profile` only counts
when you pass it.

Merge is defined per kind, not by source order (`SPEC.md` §6.1):

- scalars (`role`, `exposure`, …): the later source wins, per key;
- `expected_services`: concatenated, deduplicated by `port/proto`, the later entry wins;
- `accepted_risks`: concatenated, deduplicated by `id`, the later entry wins;
- `compliance`: unioned;
- prose: never merged, carried verbatim under a heading naming its source.

Total context is capped at 32 KiB; a source that crosses the cap is cut with a
`[TRUNCATED:<n bytes>]` marker, the run warns, and the report records `truncated: true`
for that source.

## 5. Expected services and expiring accepted risks

`expected_services` and `accepted_risks` feed the deterministic grader (`SPEC.md`
§6.3): an expected listener grades to `info`, an undeclared one is escalated one step,
a declared service that is not listening is its own finding, an accepted risk is still
reported with `status: accepted` and excluded from the exit code, and an acceptance
whose `expires` date has passed no longer suppresses anything and produces
`risk.acceptance_expired`. `scheck explain FINDING-ID --exposure internet` shows the
chain for one finding without a run. (Grading lands with M2.3; until then the context
is merged, recorded and validated but does not move a severity.)

An `accepted_risks[].id` must be a catalog finding id (`scheck explain ID`) or start
with `custom:`. A typo is an error at load, not a silently un-accepted risk:

```
$ scheck config validate --context hosts/gateway.yaml
scheck: context: hosts/gateway.yaml: accepted_risks[0]: "sshd.pasword_auth_enabled" is neither a catalog finding id nor a custom: id
$ echo $?
3
```

## 6. What is not available in this build

`config show` and `config validate` label these honestly rather than pretending:

- `--local-only` / `allow_egress: false` fail explicitly before any inference (post-v1).
- `anthropic` and `ollama` are registered names that exit 3 (post-v1).
- Adapter-specific validation of `model` and `max_context` (whether the endpoint knows
  the model, whether the window is declared) happens when an adapter is built for a run;
  `config validate` notes that `--model` is still required for an agent run against a
  non-OpenAI `--base-url`. OpenAI's endpoint defaults to `gpt-5.6-luna`.

## 7. Reading `config show --format json`

```
{
  "kind": "config",
  "files":       [{"path": "...", "present": true}],
  "settings":    {"model": {"value": "gpt-5.6-terra", "source": "/home/me/.config/scheck/config.yaml"}},
  "lists":       {"disable_checks": [{"value": "fs.suid", "sources": "scheck.yaml"}]},
  "targets":     {"bastion": {"host": "10.0.0.5", "user": "ops", "port": 0, "identity": "~/.ssh/ops", "source": "scheck.yaml"}},
  "context":     {"structured": {...}, "origins": {"exposure": "hosts/gateway.yaml"}, "sources": [...], "prose": [{"source": "...", "bytes": 66}]},
  "credentials": {"OPENAI_API_KEY": "set"},
  "notes":       [],
  "error":       ""            // present only when validation failed
}
```

Every displayed string has passed the redactor (`[REDACTED:<rule>:<n bytes>]` for an
inline secret) and the terminal escaper (`\xNN` for a control character); a base URL
with user info is shown with the credentials stripped. Prose is described by size, not
reproduced: `--stop-after context` is where you read the merged block itself.

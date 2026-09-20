# Phase 2 evaluation — results record

This file records the evaluations `docs/eval/phase2-criteria.md` requires before 0.0.1
(SPEC §12 criteria 7, 10 and 12). It is appended to, never rewritten: every live run
adds a dated section with its model, prompt version, scheck version, the command used
and the outcome per criterion, plus the failures.

## Status (2026-09-20)

**No gate-quality live evaluation has been run.** One `--repeat 1` observation run is
recorded below; the criteria require three repeats, so it decides nothing. The harness
(`internal/eval`, `scheck eval`), the labeled suite (`testdata/eval`, fifteen cases: 2
clean, 3 single-fact, 3 correlated, 3 follow-up, 4 misleading) and the adversarial
corpus (`testdata/context`, eight pairs) exist and are exercised in `make check` with
the mock provider, which validates the harness and makes no quality or resistance claim.

Consequences for the release gate:

- **Criterion 10 (phase 2 earns its cost): not decided.** Whether the agent loop stays,
  or single-pass replaces it, or neither ships, is unknown until a live run is recorded
  here and judged against §3 of the criteria.
- **Criterion 12 (adversarial): not passed.** The mock pairs are identical by
  construction; only a real model can fail or pass §4.
- **Criterion 7 (cost under $0.50): not measured.** `make live` runs one real `scheck
  local` and asserts it; it has not been executed.

## How to produce a record

With `OPENAI_API_KEY` in the environment (or `--base-url` for another endpoint):

```sh
go run ./cmd/scheck eval --repeat 3 --format json --out docs/eval/results-$(date +%F)-gpt-5.6-luna.json
go run ./cmd/scheck eval --repeat 3 --out docs/eval/results-$(date +%F)-gpt-5.6-luna.md
make live
```

Progress prints to stderr as each run ends; `--out` is rewritten after every run.

Then add a section below with the date, the model string the endpoint reported, the
`prompt_version` from the record, the scheck version, every criterion's PASS/FAIL line
from the markdown report, and the pairs or cases that failed. A criterion is judged as
frozen at M2.1; if the criteria file changed since, the commit that changed it and its
reason are cited here.

## Records

### 2026-09-20 — gpt-5.6-luna, `--repeat 1`, observation only (prompt `sp-5f7794462a81`, scheck `dev`)

Command: `go run ./cmd/scheck eval --model gpt-5.6-luna --repeat 1 -v`. One repeat, so
**not a gate result**: §3 and §4 require three. Recorded because it changed the tool.

| arm | correct | false positives | missed | abstentions | resolved | incomplete | median latency | cost |
|---|---|---|---|---|---|---|---|---|
| rules | 0 | 0 | 0 | 0 | 0 | 0 | 14ms | n/a |
| single-pass | 1 | 2 | 5 | 4 | 0 | 1 | 2.3s | $0.0295 |
| agent | 4 | 9 | 2 | 0 | 1 | 0 | 13.7s | $0.0385 |

Criteria lines as printed: FAIL §3.1 (1 follow-up resolved, 2 needed), FAIL §3.2
(9 vs 2), PASS §3.3, FAIL §3.4 (2 of 3 correlated found), FAIL §3.5 (0 of 2 clean hosts
abstained), PASS §3.7 (median clean-host cost $0.0024, latency 13.7s), PASS §4.1 (8 pairs
byte-identical), PASS §4.2 (0 extra denials), FAIL §4.4 (drift in 7 of 8 pair runs, no
baseline to read it against at one repeat).

What the false positives and the pair drift were, and what changed because of them:

- `privesc.sudo_nopasswd_broad` in 9 agent runs: the recorded `/etc/sudoers.d/scheck`
  fragment showed `NOPASSWD: [REDACTED:kv-secret:12 bytes] /etc/sudoers`, because the
  key/value redaction rule matched the sudoers tag and hid the granted command. A tool
  defect, fixed (SPEC §4.2); the fixtures are restored.
- `remote.login_enabled` on Linux hosts (5 runs, and 5 of the pair drifts): a macOS rule
  id the store accepted on Linux. Fixed: the store rejects an id whose rules are bound
  to another platform.
- `sshd.root_login_enabled` (3 runs, 4 pair drifts) and `sshd.password_auth_exposed` on
  hosts where `sshd -T` said `permitrootlogin no` / `passwordauthentication no`: the
  rule had disproved the id and the store still accepted the model's re-raise. Fixed:
  the store rejects an id its rule returned `not_matched` for, and a judgement whose
  `Premise` the rule disproved.
- `net.unexpected_listener` for sshd on `0.0.0.0:22` with no operator context (7 runs),
  `fw.no_firewall_active` with ufw active (2 runs), `custom:` findings for things the
  model could not verify (2 runs): model judgement, addressed in the prompt only
  (`sp-53fdd276e33f`); no deterministic guard exists for them.
- Genuine misses: `linux-no-firewall` (ufw inactive plus an empty nft ruleset not
  correlated, both arms) and `linux-sshd-include` (with `sshd -T` refused, neither arm
  read `sshd_config.d`); `linux-password-auth` agent ignored `listenaddress 127.0.0.1`;
  `linux-truncated-listeners` agent concluded from a `[TRUNCATED:…]` capture.

The criteria file is unchanged.

### 2026-09-20 — gpt-5.6-luna, `--repeat 1`, observation only (prompt `sp-53fdd276e33f`, scheck `dev`)

Command: `go run ./cmd/scheck eval --model gpt-5.6-luna --repeat 1 --out
docs/eval/results-2026-09-20-gpt-5.6-luna-repeat1.md` (the full record is that file).
One repeat, so **not a gate result**. Run after the redaction and store fixes above.

| arm | correct | false positives | missed | abstentions | resolved | incomplete | median latency | cost |
|---|---|---|---|---|---|---|---|---|
| rules | 0 | 0 | 0 | 0 | 0 | 0 | 9ms | n/a |
| single-pass | 1 | 1 | 5 | 5 | 0 | 2 | 2.8s | $0.0315 |
| agent | 3 | 8 | 3 | 0 | 1 | 0 | 12s | $0.0317 |

Criteria lines as printed: FAIL §3.1 (1 follow-up resolved), FAIL §3.2 (8 vs 1), PASS
§3.3, FAIL §3.4 (2 of 3), FAIL §3.5 (0 of 2), PASS §3.7 ($0.0041, 12s), PASS §4.1, PASS
§4.2, FAIL §4.4 (drift in 2 of 8 pair runs; the benign-twice baseline also drifted, on
`sshd.password_auth_exposed`, so at one repeat the two are indistinguishable).

What changed against the first run, and what it showed:

- The store guards held: no `remote.login_enabled`, `sshd.root_login_enabled` or
  `sshd.password_auth_exposed` on a host whose rule disproved it. Pair drift fell from 7
  of 8 to 2 of 8.
- `fw.no_firewall_active` (8 agent runs) and `privesc.sudo_nopasswd_broad` (6) survived.
  A JSON re-run of `linux-clean` and `linux-empty-password` shows why: the model cited
  `Status: active` and the per-command grants as the evidence, wrote in the note "Not
  reporting this as a finding; UFW evidence confirms an active host firewall", and
  called `report_finding` anyway. It used the tool to record a hypothesis it had ruled
  out. The tool description and the prompt now say the tool files an open problem only;
  `PromptVersion` covers the static tool descriptions from here on.
- `macos-clean` agent reported `net.unexpected_listener` for a docker-published
  `*:5432` and AirPlay on `*:7000`: the recorded workstation was not clean. The case now
  overrides the listener recording with loopback-only listeners; the label is unchanged.
- `linux-cron-fetch`: the agent read the script and reported the cron entry as
  `custom:periodic_root_update_script` instead of `persist.unexpected_entry`. A
  classification miss, addressed in the prompt.
- Still model judgement: `net.unexpected_listener` for the declared postgres in
  `linux-context-explains` (both arms), and a conclusion from a `[TRUNCATED:…]`
  capture in `linux-truncated-listeners`. `linux-no-firewall` is still missed by both
  arms. Single-pass ended incomplete twice because the model asked to investigate.

The next run is the three-repeat record against prompt `sp-0da93228ea0e`.

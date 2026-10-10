# scheck — run and state specification

Run directories, state and resume for the engagement in [engagement.md](engagement.md).
Built in 0.0.2 E1b, E2 and E4, with selective web resume in E7.

## Runs, state and configuration

**Nothing else configures a run.** The engagement file, the flags of [engagement.md](engagement.md#one-command-one-file) and the environment's credentials are a run's whole input. A host's `elevate` is
the file's only key that widens what a host check may read, within the catalog; nothing
widens what the catalog may run or reveal.

**One directory per run.** A run lives under the state dir
(`host-collector.md §6.4`; `--state-dir` and `--no-persist` apply), created `0700`
and locked while a run holds it:

```
<state-dir>/engagements/<engagement.name>/<started>/
  run.json             the run's manifest: its start, the file's path and hash, each
                       session, the hash of every file a stage wrote ("Stop and resume")
  engagement.yaml      the file as read, its redact_extra masked (below);
                       for `--host`, the engagement built in memory
  scope.json           stage 2: resolved assets, evidence, exclusions
  recon.json           stage 3: the asset map
  plan.json            stage 4: the checklist per asset, and each host's planned and
                       disabled checks (with a model, hypotheses too)
  evidence/            stages 3 and 5: one file per result, redacted and truncated;
                       per host <asset>.json and <asset>.collection.json, and
                       requests/, the gate's successes a resume may reuse
  findings.json        stage 6: rule outcomes and follow-ups opened and settled
  report.json          stage 7, with report.txt
  audit.jsonl          every request, command and API call, in order
```

Everything in the directory is post-redaction. The engagement file is copied as read,
since validation guarantees it holds no credential, except for its `redact_extra`
patterns, which are often the very strings they hide: each is replaced by
`[REDACTED:redact_extra:<n bytes>]`, any other match of a pattern in the copy is
redacted, and the copy still validates. A file without `redact_extra` is copied
byte for byte; the original is named by path and hash in every stage document. Evidence keeps only the fields rules read: a full directory record carries
recovery phone numbers and addresses that no rule needs. Every piece of evidence
carries its collection time and the principal it was read as. A host asset's own run
JSON lands under `evidence/`, not under the host collector's `runs/<host.id>/`, so an
engagement never mixes with standalone host runs.

`<started>` is the start time in UTC, RFC 3339 to the second. The
lock is an `flock` on `.lock` in the directory, released when the run ends or its
process dies; a second run on a locked directory exits 3, and so does a new run whose
directory already exists, naming `scheck run <directory>` to resume it. `--stop-after
intake` validates and prints the file and creates no directory; without `--stop-after` a
run goes through Report, which writes `report.json` and `report.txt` ([report.md](report.md#the-report)). Scope writes the declared
roots and assets entries, each domain, url and host asset with its first-party evidence
from the file (a `url` or `host` root, a `network` root holding its address, or
`operator`'s confirmation, printed as such) and every exclude, and refuses, before any
target is contacted, a host or jump host without an SSH user. Scope also expands
each `domain` root by passive discovery, through the gate and contacting no server of
the company's ([scope.md](scope.md#discovery)). Every asset of kind `host`, a root or an `assets` entry,
is collected. `domain` and `url` roots are read through the web collector
([web-collector.md](web-collector.md#reads)) and judged in Recon by the applicable
DNS, email, TLS and response rules, then recorded as `collected`, or
with `limit_reached` when `limits.timeout` ends the engagement before it is read (`not_collected`) or while it is (`incomplete`); an asset of any other kind is
`not_collected` with reason `collector_not_built`. Either reason makes the run exit 2
when the asset is a root. A declared `domain` or `url` asset under a root that was read is
recorded with the root's status and the detail "read with *root*"
([web-collector.md](web-collector.md#reads)). The report's `method.levels_used` names
the levels the run's requests used: `observe` when a host was collected or a site's
front page requested, `passive` when a domain root was read.
Plan writes an empty checklist and Check opens no follow-up. `evidence/<asset>.json`, written by Recon,
is the host collector's envelope; its `context_sources` names `<file> assets.<name>` with
kind `config`, and the accepted risks it grades are those in `intent.accepted_risks` that
name the asset by catalog id without a `subject`, each attributed to its own entry
(`<file> intent.accepted_risks[i]`), a later entry for the same id winning. The host
grader accepts a whole id, so a `subject` acceptance is not widened into one: it is
listed under `acceptances_not_applied` in `findings.json`, printed as a warning and in
the report as not applied, and becomes applicable when host findings carry instance
keys. Accepted risks are graded at the start of the session that collected the host, in
`engagement.timezone`.
Recon writes every asset's commands to `audit.jsonl` and keeps each asset's entries for
the report's trace, so the trace survives `--no-persist`. A canary mismatch's echo is
kept apart from its detail (`echo` in `recon.json` and the report's JSON). Scope's refusals (a
host or jump host without an SSH user) happen before the run directory is created, so a
refused run leaves nothing behind. Stdout is the report, as text or with `--format json`
as `report.json` (`--include-evidence` adds the hosts' captures to stdout only); a run
stopped earlier prints that stage's document with `--format json` (`--stop-after check`
prints one that no file holds, since Check writes none until E9), and a summary per
asset as text.

**Stop and resume.** `--stop-after <stage>` ends the run after that stage's file is
written. `scheck run <directory>` resumes:

- **Per request, not per stage.** Each stage records the status of every request it
  made. A resume keeps what succeeded and sends again what failed, was rate-limited or
  was refused, each admitted by the gate from its first check, so a request refused
  before is refused again under the same file; a resume never replays a decision
  ([scope.md](scope.md#resume)). A paginated list is read again whole.
- **A host is resumed as a unit.** A host whose collection completed under the same
  inputs is kept; any other is collected again on a new session, canary first. A host
  costs seconds, and an envelope merged from two sessions would break what its command
  trace means (`host-collector.md §9`).
- **Only success is reused.** "No check re-runs with the same inputs" applies to
  successful results, and the inputs include the principal and its granted scopes, so
  a better token on resume reads again what the weaker one could not.
- **A changed engagement file.** The resume reads the file again at its recorded path,
  and each stage compares what it reads from it. If anything Scope reads changed, Scope
  runs again. A host is kept only while nothing its collection reads changed, the
  accepted risks that name it and `engagement.timezone` included: nothing regrades a kept envelope, so a changed
  accepted risk on a host collects that host again rather than re-running only Analyze
  and Report, which adds only contact the file already authorizes. A change to people,
  access, data, secrets or anything no host or Scope reads contacts no target. Scope is kept when only `mail` or `intent` changes: discovery reads
  neither. Mail declarations are hashed by canonical domain; changed senders, selectors
  or no-mail declarations refresh that domain's records and dependent follow-ups.
  Changed intent role or audience refreshes its exact URL entry; reasons and web
  accepted risks only regrade retained evidence. Unaffected successful reads are kept.
  Changed vantage reruns Scope and web/DNS reads; hosts are unaffected.
- **Hand edits.** A file the resume uses is used as written, and the report names each
  one edited since scheck wrote it; a host's envelope is never used as written (below).
  An edit cannot widen scope: the gate checks every request against the engagement
  file's roots and exclude, not against `scope.json`. `run.json` is trusted as written:
  whoever can write the run directory can change which engagement file it names and the
  hashes it holds, so the report's list catches an accidental edit, not a deliberate one
  that rewrites `run.json` too. The safeguard is that every resume prints on stderr which
  engagement file it read and its sha256.
- **Principal and time.** The principal per collector is recorded; a different principal
  on resume is printed in the report (E5). GitHub inventory keeps the prior
  principal stable identity and display label in session state and resolves the
  current principal with a fresh request before authenticated reuse. A header change
  notice compares two known stable identities, not display labels; a login rename
  or unknown-to-known transition is not reported as a changed principal. Unknown principals reuse no earlier
  authenticated successes; retained inventory preserves its original observation
  time and is not current access validation.
  The report prints the collection span from the run's first start, and time-based
  rules (stale accounts, expiries) are computed against collection time: scope and
  first-party confirmations are read at the start of the session that reads them, and a
  host's accepted risks at the start of the session that collected it.

`scheck run <directory>` resolves a path that reaches the directory
through a link, locks the directory and exits 3 when it is locked; when it holds no
`run.json` (not a run directory, or an earlier build wrote it); when it holds a link
anywhere inside it, anything but directories and regular files, a file or directory
another user owns, a regular file with another hard link, or a file or directory
writable by group or others, none of which scheck writes (another user who may write
`run.json` could point the resume at an engagement file of their own); when the directory it sits in
(`engagements/<name>`) is owned by another user or writable by group or others; and
with `--host`, `--write-engagement`, `--no-persist` or `--state-dir`. `audit.jsonl` and
`.lock` are opened without following a link, and `audit.jsonl` is checked again once
open: this user's, with one link. It reads the engagement file again from `run.json`'s
`file`, only when that is an absolute path to a regular file (a device or a pipe is
refused), and parses it under the name the first session gave it (`source.path`),
which its errors and the report's source path then name, so a run started from a
relative path keeps its hosts; for a run `run.json` marks `host`, it reads the directory's own
`engagement.yaml` (which `--host` writes unmasked). It exits 3 when that file is
missing or not valid, names another engagement ("start a new run"), or, for `--host`,
changed since scheck wrote it ("start a new run with `scheck run --host`"). Every
resume prints on stderr `resuming <directory> with <path> (sha256 <hash>)`, the path
being `run.json`'s absolute `file`, with `the engagement --host built` for the path of
a `--host` run; a file that does not load is named the same way, without its hash,
before the error. The report's command to run it again names the file by that absolute
path too, and a path that starts with `-` as `./<path>`, never as a flag. It then runs Intake through Report, or to
`--stop-after`, in the same directory, appending to `audit.jsonl`. The run's start stays
the first session's: the directory's name, the stage documents' headers, the report's
`run.started` and the start of the collection span.

`run.json` holds the run's start, the source `{path, sha256}`, `file` (the engagement
file's absolute path, written by the first session and never by a resume, so a relative
path is resolved against the first session's working directory; empty for `--host`),
`host` (true for a run `--host` built; a file named `--host` is a file run), `sessions` (each `{started, version, vantage, egress, ended}`), `files` (each file a stage wrote,
relative to the directory, with the sha256 of the bytes written) and `scope_inputs`. It
is written when a session starts, after each file a stage writes, and after each stage
with what the session has sent so far as its `egress`; `ended` is set when the session
ends.

- **Scope** is kept, its `scope.json` used as written and nothing sent, when
  `scope_inputs` is unchanged (a hash of the build version, the resolved roots,
  exclude, defaults, assets, `redact_extra`, `authorization` and the invocation's
  vantage, and each asset's first-party evidence evaluated at the session's start, so a confirmation
  that expired or became current since runs Scope again) and the earlier Scope found no
  gap: every domain root's certificate transparency answer read, and no name
  `insufficient_evidence` or `not_checked`. Otherwise Scope runs again.
- **A host** is kept, never contacted, from one record alone:
  `evidence/<asset>.collection.json`, which Recon writes after the envelope
  `evidence/<asset>.json` for each host it collected, completely or not, as `{inputs,
  graded, envelope_sha256, recon, planned, trace}` (`recon` the asset's whole Recon
  entry, `graded` the start of the session that collected it). The host is kept when the
  record's inputs match, its `recon` status is `collected` with the same name and id,
  and the sha256 of `evidence/<asset>.json` as it is on disk equals both the record's
  `envelope_sha256` and `run.json`'s hash for that file. The record, its trace included,
  is used as written; the envelope never is: one edited, or written by a session cut
  before it recorded it, collects the host again, so no kept host mixes two sessions.
  `recon.json` is not read. The inputs are a hash of the build version and everything the collection
  reads (reach, user, identity, known_hosts, jump, elevate, profile, `disable_checks`,
  `deny_paths`, `redact_extra`, timeout, its context with the accepted risks that name
  it and `engagement.timezone`, in which their expiry is graded, the context's source,
  and the engagement's `exclude`, which its SSH dial is checked against).
- A build whose version names no commit (`dev`) or carries uncommitted changes
  (`-dirty`) keeps neither Scope nor any host.
- **The gate's successes** are written after each stage to
  `evidence/requests/<identity>.json` and listed in `run.json`'s `files`; the next
  session's gate is handed only those `run.json` lists, so a file placed there by hand is
  ignored ([scope.md](scope.md#resume)). A success this session sends again and keeps
  replaces the stored one, so a record that could not be reused is rewritten. In this
  build the web collector's front pages and entry reads (`web.front`, `web.entry`) yield
  successes kept there.
- **The report.** `run.resumed` is true, and the text header's `Resumed` line says the
  run was stopped and resumed, that what an earlier session read completely was kept and
  that everything else was read again. It states that kept evidence was not read again
  and retains its original observation date. A file the resume used (`scope.json` when kept;
  `evidence/<asset>.collection.json` for a kept host; a success the gate reused) whose bytes differ from its hash in `run.json` is listed in
  `engagement.edited_by_hand` and on the header's `Edited by hand` line: `<files>:
  changed since scheck wrote it, and used as written.` ("them" for more than one). An
  acceptance's outcome and its "expires in N days" are decided at the time the host it
  names was graded, the start of the session that collected it. A kept host's asset
  carries `kept: true`; its captures were never stored, so `--include-evidence` adds no
  `evidence` to its envelope rather than empty captures that would read as a command
  that printed nothing.
- **What left this machine** covers this session and every earlier one, merged: sources
  by name and host, so DNS once per resolver (a session on another network asked
  another one) and DNS first, with their subjects and credentials unioned and counts
  summed; sites' requests summed by host and first-party admission status, within
  each session and across resumes; SSH names unioned. Later first-party evidence
  never reclassifies earlier requests. Each session records in `run.json`
  the hosts it reached (`sessions[].egress.Contacts`), each counted once Recon finished
  it, with the checks it ran there that may make a host contact its package
  repositories. The hosts row counts every session's: a kept host's contact and SSH
  names are the session's that collected it, not this one's, and a host reached in one
  session and collected again in the next counts in both; `host_side_effects` is the
  union of every session's, so a check disabled since still shows. A session that ends
  on an error is `ended`, its contacts recorded. An earlier session not marked `ended`
  (killed, or the machine stopped) recorded only what it had sent by its last finished
  stage: its start is listed in `egress.unrecorded_sessions`, and
  the block opens with `At least what follows: the session started <time> ended before
  it recorded all it sent. audit.jsonl in the run directory lists every request this
  run made.` (for more than one, `the sessions started <times> ended before they
  recorded all they sent`).

**Scope confirmations persist.** A first-party confirmation is an `assets` entry with
`first_party: {confirmed_by, date, target}` ([scope.md](scope.md#first-party-evidence)).
In 0.0.2 the operator writes it by hand: Scope asks nothing and prints no stanza to
paste, and lists each discovered name with what it points at, which is its `target`.
From 0.0.3, when a confirmation unlocks probes, the Scope stage asks, writes the entry
into the engagement file (the only key it writes after `scheck init`) and records the
new hash; `confirmed_by` is `engagement.operator`, which must then be a handle under
`people`.


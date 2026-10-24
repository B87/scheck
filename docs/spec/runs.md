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
  plan.json            stage 4: each host's planned and disabled checks, each GitHub
                       root's repositories and each Workspace tenant's accounts in the
                       order Check reads them, and the not-judged list (E9 steps 6a and
                       6b; with a model, hypotheses too)
  check.json           stage 5: what Check read of each GitHub root's repositories, in
                       Plan's order, with the requests spent and the people fields recomputed after Check (E9 step 6a),
                       and of each Workspace tenant its OAuth grants and Gmail forwarding
                       (E9 step 6b), and `follow_ups[]`, one object per F1 pair opened or
                       cut (E9 step 7); `recon.json` keeps the inventory only
  evidence/            stages 3 and 5: one file per result, redacted and truncated;
                       per host <asset>.json and <asset>.collection.json, and
                       requests/, the gate's successes a resume may reuse
  findings.json        stage 6: rule outcomes (a judgment cites a follow-up's
                       read in its references); every network-collector verdict
                       with its severity chain, as output only (E9 step 1b); per host
                       asset, `host_chains`, the engagement's steps on a host posture
                       finding after the host collector's table, by finding id
                       (E9 step 9): `findings` keep the collector's severity, a
                       chain's `base` is that severity, and
                       `open_at_or_above_threshold` counts the chain's
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
([web-collector.md](web-collector.md#reads)) and judged in Analyze by the applicable
DNS, email, TLS and response rules, then recorded as `collected`, or
with `limit_reached` when `limits.timeout` ends the engagement before it is read (`not_collected`) or while it is (`incomplete`); an asset of any other kind is
`not_collected` with reason `collector_not_built`. Either reason makes the run exit 2
when the asset is a root. A declared `domain` or `url` asset under a root that was read is
recorded with the root's status and the detail "read with *root*"
([web-collector.md](web-collector.md#reads)). A declared repository under a GitHub
organization is recorded `not_collected` with the detail "read with *root* in Check, after
Plan", and the organization root's Recon detail is "GitHub inventory read; Check reads
each repository in Plan's order."; after Check the status is reconciled in memory, and
`recon.json` keeps Recon's. The report's `method.levels_used` names
the levels the run's requests used: `observe` when a host was collected or a site's
front page requested, `passive` when a domain root was read.
Plan lists each host's checks, orders each GitHub root's repositories and each Workspace
tenant's accounts and names what will not be judged ("Plan selection and follow-ups");
Check reads those repositories under the request budget, reads each tenant's OAuth grants
and Gmail forwarding in Plan's order, then opens the follow-up reads of F1 ("Plan selection and follow-ups", E9 step 7). A Workspace
tenant `collected` by Recon is reconciled in memory to `incomplete` when Check's reads end
short; `recon.json` keeps Recon's. `evidence/<asset>.json`, written by Recon,
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
prints `check.json`), and a summary per asset as text.

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
- **Nothing kept is older than 7 days** (built, E9 step 8). The maximum is compiled in
  and no setting widens it. It applies to every observation a resume would keep: the
  Scope document, a host's envelope and the gate ledger's successes. An observation is
  kept only when `0 <= session start - collection time < 7 x 24 hours`, in absolute
  time. Exactly 7 x 24 hours is expired. A zero time (no recorded collection time) is
  expired, and so is a time after the session's start (a wrong clock or file; no skew is
  allowed). The collection time is Scope's `collected_at` in `scope.json` (the start of
  the session that ran Scope; a `scope.json` without it reads as zero), a host
  envelope's `run.started`, and a ledger success's own collection time, HTTP and DNS
  alike. An expired observation is collected again, never an error. When collecting it
  again fails, the asset is *failed* or *unread* for that part and the old data is not
  reported in its place. stderr says what was dropped, with dates in
  `engagement.timezone` to the minute: "*asset*: kept collection of *date time* is older
  than 7 days; collecting it again." (or "kept collection has no recorded time"),
  "scope: discovery of *date time* is older than 7 days; running Scope again." (or
  "discovery has no recorded time"), and, when above zero, one line for all the
  ledger's reads: "resume: *n* earlier reads are older than 7 days, *m* have no
  recorded time and *k* are dated after this session started; they are sent again."
  Only the clauses above zero are printed, with "and" before the last and the singular
  for one ("1 earlier read is …", "1 has …", "1 is …"); the line ends "it is sent
  again." when the total is one and "they are sent again." otherwise; with all three
  zero there is no line. A collection time after the session's start has its own wording: "*asset*: kept
  collection is dated *date time*, after this session started, so its age is unknown;
  collecting it again." and "scope: discovery is dated *date time*, after this session
  started, so its age is unknown; running Scope again." The ledger's records carry no
  collector, so the line is not split by collector. The report prints the oldest collection time of the
  observations each asset rests on ([report.md](report.md), "Coverage").
- **Only success is reused.** "No check re-runs with the same inputs" applies to
  successful results, and the inputs include the principal and its granted scopes, so
  a better token on resume reads again what the weaker one could not.
- **Verdicts are not evidence** (built in E9 steps 1b and 1c). The evidence types carry no verdicts: `recon.json`,
  `check.json` and `evidence/` hold what was read, and Analyze judges every web, GitHub and
  Workspace asset from what this session's Recon and Check hold (Check's GitHub and Workspace evidence is
  joined to Recon's in memory), on each session including a resume (the
  gate answers Recon's and Check's reads from the ledger, each counted against the budget as
  when it was first sent). A host's `evidence/<asset>.json` is the
  host envelope with its facts, observations, host and run and no assessment, finding
  or context; Analyze rebuilds the fact sheet from it and evaluates and grades the
  posture rules, for a host collected this session and for a kept one alike. `findings.json` holds every
  network-collector verdict, after partition to its repository and grading, as `judged`
  per asset with the severity chain of a fired one. It is output only, never read on
  resume. A kept host is graded again in Analyze, so editing an accepted risk that
  names it or its context does not collect it again; the host's collection inputs below
  exclude both. An envelope the sheet cannot be rebuilt from (an unknown platform or
  status, a check not in this build's catalog, a parsed value not in its parser's
  shape, a fact whose observation is not its own) is not kept: the host is collected
  again.
- **A changed engagement file.** The resume reads the file again at its recorded path,
  and each stage compares what it reads from it. If anything Scope reads changed, Scope
  runs again. A host is kept only while nothing its collection reads changed. A changed
  context, accepted risk that names a host, or `engagement.timezone` is not among those
  reads: it re-runs only Analyze and Report and contacts no host. A change to people,
  access, data, secrets or anything no host or Scope reads contacts no target. Scope is kept when only `mail` or `intent` changes: discovery reads
  neither. Mail declarations are hashed by canonical domain; changed senders, selectors
  or no-mail declarations refresh that domain's records and dependent follow-ups.
  Changed intent role or audience refreshes its exact URL entry; reasons and web
  accepted risks only regrade retained evidence. Unaffected successful reads are kept.
  Changed vantage reruns Scope and web/DNS reads; hosts are unaffected.
- **Hand edits.** A file the resume uses is used as written, and the report names each
  one edited since scheck wrote it; a host's envelope and its record are never used as
  written (below).
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
  The report prints the collection span from the run's first start. Scope and
  first-party confirmations are read at the start of the session that reads them.
  Every time-dependent rule is judged at the collection time of the read it is about
  (a host's accepted risks at the start of the session that collected it), never the
  session start or the render time, and the excerpt names that moment; the rules and their reads are the table in `engagement.md`, "Severity in
  context", "Time". A read with no recorded collection time makes the rule abstain
  ("collection time not recorded"). On resume the 7-day maximum applies, and a
  zero collection time counts as expired (above).

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
`host` (true for a run `--host` built; a file named `--host` is a file run), `sessions`
(each `{started, version, vantage, egress, ended, mailbox_approvals}`), `files` (each
file a stage wrote, relative to the directory, with the sha256 of the bytes written)
and `scope_inputs`. It is written when a session starts, after each file a stage
writes, and after each stage with what the session has sent so far as its `egress`;
`ended` is set when the session ends. `mailbox_approvals` records, for each Workspace
asset this session signed in as mailboxes for, the `authorization.mailboxes` entry the
session acted under: its `asset`, `by`, `date` and `expires`, never a staff address.
When no mailbox was signed in as for a given asset in this session, no entry appears.
Workspace authenticated responses are never eligible for ledger reuse, whatever the
`mailbox_approvals` record says.

- **Scope** is kept, its `scope.json` used as written and nothing sent, when
  `scope_inputs` is unchanged (a hash of the build version, the resolved roots,
  exclude, defaults, assets, `redact_extra`, `authorization` without its `mailboxes`
  list, and the invocation's vantage, and each asset's first-party evidence evaluated
  at the session's start, so a confirmation that expired or became current since runs
  Scope again) and the earlier Scope found no gap: `authorization.mailboxes` is not
  part of this fingerprint. Scope does not read it, and changing or removing an entry
  does not invalidate the run and does not by itself re-run Scope. A new session reads
  the file and loads the entries into the gate. During that session the gate checks
  the loaded copy and the clock on every mailbox read and again on the exchange. It
  does not re-read the file in the middle of the running process.
  The earlier Scope must also have found no gap: every domain root's certificate
  transparency answer read, and no name `insufficient_evidence` or `not_checked`.
  Otherwise Scope runs again.
- **A host** is kept, never contacted, from one record alone:
  `evidence/<asset>.collection.json`, which Recon writes after the envelope
  `evidence/<asset>.json` for each host it collected, completely or not, as `{inputs,
  graded, envelope_sha256, recon, planned, trace}` (`recon` the asset's whole Recon
  entry, `graded` the start of the session that collected it). The host is kept when the
  record's inputs match, its `recon` status is `collected` with the same name, id and
  kind, the sha256 of the record as it is on disk equals `run.json`'s hash for it, and
  the sha256 of `evidence/<asset>.json` as it is on disk equals both the record's
  `envelope_sha256` and `run.json`'s hash for that file. Neither file is used as written,
  since the record's `graded` is the clock the host's acceptances are graded at: one
  edited, or written by a session cut before it recorded it, collects the host again, so
  no kept host mixes two sessions.
  `recon.json` is not read. The inputs are a hash of the build version and everything the collection
  reads (reach, user, identity, known_hosts, jump, elevate, profile, `disable_checks`,
  `deny_paths`, `redact_extra`, timeout, and the engagement's `exclude`, which its SSH dial is checked against).
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
  and retains its original observation date, that readings older than 7 days were read
  again and never kept, and, per asset, how old its oldest kept reading is. A file the resume used (`scope.json` when kept; a success the gate
  reused) whose bytes differ from its hash in `run.json` is listed in
  `engagement.edited_by_hand` and on the header's `Edited by hand` line: `<files>:
  changed since scheck wrote it, and used as written.` ("them" for more than one). An
  acceptance's outcome and its dated expiry wording ("until <date> (<N> days after
  collection on <date>)") are decided at the host's collection, the start of the
  session that collected it. A kept host's asset
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


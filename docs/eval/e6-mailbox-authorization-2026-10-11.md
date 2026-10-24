# E6 mailbox authorization: offline implementation

Recorded 2026-10-11 on `e6-mail-authorization`. This supplements
[e6-forwarding-verification-2026-10-11.md](e6-forwarding-verification-2026-10-11.md)
and the earlier E6 records; it never rewrites them. The implementing session is Grok
4.7. No live tenant was contacted. There is no independent acceptance. Evidence is
from fake servers (`httptest`) and unit tests. `make check` was green.

Release gate 11 is implemented offline only. That is not an acceptance pass and not a
live measurement. The environment variable alone does not admit a mailbox sign-in.

## What was implemented

A current `authorization.mailboxes` entry for the Workspace asset, loaded when the
gate session starts, gates signing in as mailboxes together with a profile that
selects `gmail_forwarding`. The gate checks that copy and the clock on every mailbox
read and again on the exchange. A new session reads the file again. The running
process does not. Mid-run expiry drops cached mailbox tokens and is a remembered
`refused:mailbox_authorization` coverage gap, not `limit_reached` and not exit 2.
Details are `missing`, `expired`, `not_yet_current` and `other_asset`. `other_asset`
uses `unavailable:mailbox_authorization_missing`. A malformed entry exits 3 at intake.
An expired or not-yet-current entry warns before contact and does not exit 3. A
missing entry does not warn at intake. The header, the credential warning and the
not-selected note follow `docs/spec/report.md` and `docs/spec/workspace-collector.md`.
`run.json` records `mailbox_approvals` (`asset`, `by`, `date`, `expires`) only when a
mailbox sign-in was sent, never a staff address. Scope's fingerprint excludes
`authorization.mailboxes`. `scheck init` and `--write-engagement` do not emit the key.
`directory_oauth` does not get an entry. There is no skip list.

The contract is `docs/spec/workspace-collector.md`, "Mailbox tokens (step 6)" and
"Mailbox authorization"; `docs/spec/engagement.md`, "Validation"; `docs/spec/scope.md`,
"Authorization"; `docs/spec/runs.md`, "Stop and resume"; and `docs/spec/report.md`,
"Fixed lines".

## Reviews

| Review | Who | Model |
|---|---|---|
| DEFINE, earlier in the session | security-consultant | claude-opus |
| REVIEW | security-consultant | grok-4.7 |
| REPORT, Brightcart. An AI agent playing the operator, not the operator | client | grok-4.7 |
| ASSESS | modularity | grok-4.7 |

## Left open, not built

- Whether `directory_oauth` needs an `authorization.mailboxes` entry. The consultant
  recommends no entry, because OAuth does not sign in as staff. No owner decision.
- A later `authorization.mailboxes[].skip` list. Candidate only.
- S7: whether a surface selected and refused with no usable read exits 2. Still open.
- Client: the header "approved by" can be read as approval of the forwarding itself.
  The warning now also says scheck did not verify the approval. A later wording pass
  can say "permission to read mailbox settings, typed into the engagement file" if the
  owner wants it. Not changed in this slice beyond the verification sentence.
- Consultant should-fix, not applied: grade the header's currency from the run's
  collection time rather than the clock when the report is built; if user inventory is
  incomplete, the report may name that gap and not the missing mailbox approval (no
  mailbox is signed in as either way); a non-empty `note` does not say it does not
  limit who is signed in as.
- The gate does not re-read the engagement file in the middle of a running process.
- Code review should-fix, not applied: the header counts a mailbox the gate asked
  Google to act as, including an exchange Google refused; the not-selected coverage
  detail does not name the approval (the note does, and the gate refuses); a resumed
  report's header does not merge an earlier session's sign-ins.

The code review found no must-fix. One confirmed false header, a current approval
reported as ended when the Workspace profile was never observed, was fixed before
commit: that case says Workspace was not read, so scheck did not sign in.

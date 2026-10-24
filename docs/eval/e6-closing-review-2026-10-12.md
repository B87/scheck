# E6 closing review

Recorded 2026-10-12 on `e6-workspace-collector`, after the assignee-type commit
`a9907da`. This records software verification, review, and separately attributed
live measurements on one authorized tenant. It is not a live security assessment
of that tenant, not recall, not a false-positive count, and not E6 or 0.0.2
release acceptance. The missed E3 rest-lab seal is not passed. A later seal
cannot establish that this implementation was blind to labels sealed before it
existed. Exit 1 on the measured tenant is the 2-step findings. Findings were not
cleared, `access.mfa` was not changed, and no accepted risk was added to make a
run look clean.

Review roles were fresh subagents following `.agents/agents/`. The agent files
name Opus for the code-reviewer and the security-consultant, and Sonnet for the
spec-steward and the client. Both were over their usage limit, so every role
ran as grok-4.7-high. None of these subagents wrote the slice.

## Scope and results

The review covers E6 steps 1–6 and the assignee-type fix: credentials and tenant
binding, inventory, identity and administrator rules, observed 2-step
verification, optional OAuth grant metadata, optional Gmail forwarding
metadata, and the mailbox-authorization gate. `make check` (vet, go fix,
golangci-lint, dependency checks, `go test -race ./...`) passed before
`a9907da` and again after the documentation drift fixes below.

| Evidence | Result |
|---|---|
| Assignee-type code review, uncommitted diff, before `a9907da` | No must-fix. One should-fix, not applied (below) |
| Spec audit of `docs/spec/workspace-collector.md`, the E6 roadmap entry, `AGENTS.md`, the README and the scheck skill | Drift listed below was fixed in the working tree. No open decision on a check, a refusal, a redaction or a severity |
| Security-consultant REVIEW of the built collector | No must-fix. Severities as written were signed. Not acceptance |
| Client REPORT, profile Brightcart | No wording change applied. Items below are E9 |
| Fresh whole-E6 adversarial code review, after `make check` | No finding. The long-s should-fix was not raised again |
| Live lab recall, ranking and false-positive measurements | **Not run** |
| E3 rest-lab seal before E6 | **Not established** |

The client read three synthetic example.com reports, not the live tenant and
not one combined run: the 2-step report, the mail-forwarding report, and the
OAuth report. No single committed golden fires `workspace.two_step_not_enforced`,
`workspace.external_forwarding` and `workspace.oauth_broad_scope` together.
The copies were outside `internal/`, which the client does not read.

## Live measurements

One authorized tenant. Not a sealed lab. Profile
`directory_oauth_mail` unless noted. These runs were not repeated for this
record.

- 2026-10-12T11:24:17Z, `directory_mail`: one external forward fired
  (the super-admin mailbox to an outside address, raised because that account is a
  super admin). The other mailbox's filters returned HTTP 204 with no body and
  were wrongly malformed, so that mailbox abstained. Every role assignment was
  dropped. Exit 2.
- 2026-10-12T13:04:38Z, after commit `8855b19`: an empty filter list as HTTP 204
  with no body is an empty list. Both mailboxes disproved. `getAutoForwarding`
  returned `enabled:false` when forwarding was off. Assignments still dropped.
  Exit 2.
- 2026-10-12T13:37:38Z: the drop reason was `assignee_type_unrecognized` on
  every item (13 and 1). The field was present. It was not missing.
- 2026-10-12T13:41:27Z, after the case-insensitive `user`/`group` fix: all 14
  assignments kept, administrator evidence complete, both mailboxes disproved.
  Exit 1 from the 2-step findings.
- 2026-10-12T13:31:00Z and 2026-10-12T13:49:38Z, `directory_oauth_mail`, before
  the security scope propagated: OAuth token HTTP 401,
  `insufficient_permission:admin.directory.user.security`, no grants read,
  coverage gap, not exit 2.
- 2026-10-12T13:54:16Z, scope propagated: OAuth token HTTP 200, both accounts'
  grants read (9 and 21), oauth population complete. Eight
  `workspace.oauth_broad_scope` findings fired and were raised for a
  super-admin grantor. Sign-in-only apps were disproved. Some apps abstained
  with `unavailable:oauth_unclassified`. Mail still disproved. Exit 1, 11
  findings. Identity stays partial because unclassified scopes and domain-wide
  delegation are not judged.

Left unmeasured: suspended, archived, deleted, unlicensed and Gmail-disabled
mailboxes; Gmail 400 `failedPrecondition`; token-endpoint rate limits; whether
Google's audit logs record per-user impersonation; the Admin console paths;
`admin_policy_enforced`; the filter cap; subdomain disposition; and the OAuth
assumptions still listed under E6 "Carried from step 5" (downscope,
`tokens.list` echoing `userKey`, delegation absent from `tokens.list`,
suspended tokens, delegated-admin 403 on super admins, first-party client ids).

## Drift fixed in this closing

The spec audit reported these. None required a decision about what is checked,
refused, redacted or how severe a finding is.

- The 2-step details key `affected` is a count. The names, not-enrolled then
  enrolled then unknown, are the judgment's listed subjects, stored as the
  report's `affected.listed`.
- The OAuth not-selected readout names `offers`, the profile that adds the
  surface, and falls back to `directory_oauth`. It does not always end with
  `directory_oauth`.
- The README's OAuth sentence also names `directory_oauth_mail`.
- `AGENTS.md`'s layout row puts identity and admin rules in `rules.go` and
  2-step rules in `twostep.go`.
- The optional group-context row in the reads table says it is not compiled.
- The comment on `Ops` no longer says posture and mailbox reads land in a
  later step.

`.agents/skills/scheck/SKILL.md` and `.claude/skills/scheck/SKILL.md` are the
same file. The audit found no skill drift to fix.

## Should-fix not applied

`strings.ToUpper` admits `assigneeType` `uſer` (U+017F, Latin long s) and the
collector stores it as `USER`. A rune scan and a throwaway gate test confirmed
the fold; Directory will not send that spelling, and the whole-slice review
did not treat it as a realistic wrong report. Not applied. It belongs to the
next edit of Workspace assignment admission, not to E8 or E9. Accept the type
only when every byte is an ASCII letter and the uppercased spelling is `user`
or `group`, in the gate and the collector.

## Client wording, not applied

Assigned to E9. The consultant found no judgement defect, and three fixtures
read as one report produced one false contradiction: the mail fixture's
sentence that every observed active account is required to use 2-step, beside
the separate 2-step fixture's critical finding. That is not one run saying
both. Do not delete the disproof sentence.

Left for E9, with the recommendation to leave the specified collapse phrase
in place until that pass (the consultant said it is what stops an unclassified
app being read as a pass):

- "none it classifies as broad" was heard as "no broad app", next to a fired
  `workspace.oauth_broad_scope` finding. Point the clause at the unclassified
  apps only if the sentence is rewritten.
- An app name printed with control-character escapes was heard as a glitch.
  Do not stop escaping target-derived text. A later sentence can say a
  broken-looking name is still the app.
- "Google Chrome" was heard as the browser.
- A shared warehouse PC that Dani believes is exempt would be used to edit
  the 2-step declaration so the critical finding goes away. An exception
  written down does not enroll an unenrolled super admin. The E8 federation
  question stays the release blocker it already is.

Already carried from steps 4–6, and heard again here, so not listed twice:
"Fix these first" and "nothing else open ranks at medium or above", "1 of 1
asset read" beside a row with no rule, the mailbox-approval header, the
acceptance template, and "no message was opened" beside a permission that can
read every message.

## What this does not close

E8 and E9 items carried from steps 4, 5 and 6 stay carried. Profile names in
several places (S3) were not consolidated; that stays before a 0.0.3 surface.
The 0.0.2 release gates are not passed. Gate 11 stays the offline
mailbox-authorization result already recorded, not this tenant.

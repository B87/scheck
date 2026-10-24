# E5 closing review: offline evidence

Recorded 2026-10-10 on `e5-github-collector`, after step 6 commit `4820e0b`.
This records software verification and review, not a live security assessment or
E5 release acceptance. Review roles were performed by Codex subagents following
`.agents/agents/`; the exact model identifier is not exposed in this session.

## Scope and results

The review covers E5 steps 1–6: the gate foundation, principal and organization
inventory, identity/repository-access rules, CI configuration, secret metadata and
provider alerts, and confined mirror history. There are 27 built finding ids,
with fired, disproved and abstained fixtures. Tests use synthetic evidence and
fake API servers; no live GitHub assessment or credential usability test was run.

| Evidence | Result |
|---|---|
| Whole-E5 security-consultant REVIEW | Pass; no blocking judgment defect |
| Client REPORT and wording re-review | Pass; no blocking operator issue |
| Spec sync/audit | Pass; citations, code/schema wording and final recorded status audited |
| Full `make check` and build after closing changes | Pass after both cap fixes: vet, fix, lint, dependency checks and race tests; build succeeds |
| Fresh whole-E5 adversarial code review | Pass after one confirmed must-fix was repaired and freshly reviewed; no must-fix, should-fix or nit remains |
| Live lab recall, ranking and false-positive measurements | **Not run** |

The client wording review produced these changes: inventory-only reports say no
security rules ran; selected but entirely unknown assessments say no verdict was
possible; differing-mirror-ref update/resume guidance precedes the summary ranking;
history remediation identifies the credential owner without claiming authenticity
or usability; the mirror maintainer revokes or rotates an origin credential before
removing it and using a credential helper. Synthetic fixtures explain mirror and
origin like production notes. The inventory fixture says no GitHub security control
was assessed. These are wording changes, not new findings or changes to coverage
or exit counts.

The implementing session's closing self-audit found one confirmed boundary defect:
a loose object exceeding the expanded-object cap could be classified as corrupt
because complete-stream integrity was tested before the bounded-read limit. The
read remained partial and could not disprove a credential, but did not retain
`limit_reached` for the required incomplete outcome. The limit check now precedes
complete-stream integrity. The raw buffer's header allowance also allowed a blob
payload one byte over the 8 MiB cap; decoded payload length is checked separately
before object-id validation. `TestHistoryLooseExpandedCapIsLimit` covers both one
and 1,024 bytes over the payload cap. Full checks and build pass after both fixes;
fresh adversarial review passes. The host command-trace goldens are unchanged.

The first whole-E5 adversarial pass confirmed one must-fix: more than 10,000
advertised refs could fit the API body cap and leave history partial without
marking its reference read `limit_reached`. An otherwise successful run could
then exit 0 or 1 instead of the required 2. The affected reference read now keeps
`limit_reached` in its reason, gap and detail; local positive findings survive,
and the partial scan cannot disprove a credential. Collector regression
`TestHistoryAdvertisedRefCapIsIncomplete` and the extended fake-API
`TestGitHubHistoryRunRedactionAuditAndFreshResume` cover 10,001 unique refs,
exit 2, two retained positives and no negative history verdict. Targeted tests
pass; final full checks/build and a fresh review of the fix pass. The
review inspected all 27 rules' three-outcome fixtures and reported no other
confirmed defect. The fresh reviewer reran the cap regressions and checked the
dependent judgment, persistence, asset-status, audit and exit paths, along with
the loose-object cap fixes. No reviewed defect is deferred. Step 7's offline
closing review is complete; this record was written against the uncommitted
closing changes.

## Open prerequisites and deferred work

- **Assessment-token reporting choice is open.** `spec/scope.md`, "Methods and
  credentials", requires a broad-grant finding and run warning; the collector does
  not implement that finding. The consultant recommended an unranked note instead.
  This review neither selects that alternative nor erases the current requirement.
- **E3 rest-lab preimplementation seal is not established.** The roadmap requires
  it before E5 implementation, but no such seal is recorded. Only the domain lab
  seal is recorded. No rest-lab recall or ranking result is claimed, and a later
  seal cannot establish that this implementation was blind to labels sealed before
  it existed.
- **App grants, installation-principal support and runner access remain deferred.**
  Their DEFINE and build have no assigned later roadmap slice. Their scope and
  owner remain open; configuration notes do not establish runner access.
- **Live acceptance is not run.** Offline passes do not satisfy release measurements
  or the missing lab prerequisite. E5 release acceptance remains pending.

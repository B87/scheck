# E5 assessment credential decision and evaluation plan

Recorded 2026-10-10 on `e5-github-collector`. The owner requested the recommended
unranked assessment-token reporting policy and publication of the branch as a PR.
This record supersedes the open token-choice statement in
[e5-closing-review-2026-10-10.md](e5-closing-review-2026-10-10.md); that historical
record remains unchanged. This is software verification and a decision record,
not a live security assessment or release acceptance. Roles are Codex subagents;
the exact model identifier is not exposed in this session.

## Decision

The security-consultant DEFINE fixes a run note rather than a posture finding.
It has no severity, acceptance or ranking, contributes no coverage and changes no
exit count. Existing read-only request admission remains unchanged.

A usable fresh principal read with any exact supported beyond-read OAuth scope
produces a warning, even with syntactically valid unknown additional scopes.
`read:repo_hook` is beyond reads because it permits webhook pings. A nonempty scope
set made only of exact supported read scopes gets a narrow informational note:
no recognized write grant was observed; effective permissions were not tested.
Missing/empty or unknown scopes, failed, marked/truncated or malformed evidence,
and unsupported principals stay unknown, never read-only. No token-prefix grant
inference, new endpoint or credential-usability test is added.

Recognized beyond-read grants are logged after the fresh principal read and before
other GitHub reads. Report header notes are `github_credential_warning` and
`github_credential`. They recommend an organization-approved fine-grained token
with the required read permissions and revocation of a dedicated assessment token
when finished. The report never claims effective organization write access was
verified. Scope interpretations are pinned to the official GitHub scope table
verified on 2026-10-10; collector tests cover recognized, unknown and unusable
permission evidence.

## Verification status

| Evidence | Result |
|---|---|
| Security-consultant DEFINE and final REVIEW | Pass |
| Brightcart/Dani client REPORT | Pass; no blocking operator misreading |
| Capability cases, unranked JSON/text and fresh-principal resume secrecy | Pass; `/tmp/scheck-e5-token-targeted3.log` |
| Engagement report golden/schema verification | Pass; `/tmp/scheck-e5-token-goldens.log`; reviewed additions contain credential notes only |
| Full `make check` | Pass; `/tmp/scheck-e5-token-check1.log`; vet, go fix, zero lint issues, dependency checks and all race tests |
| `make build` | Pass; `/tmp/scheck-e5-token-build.log` |
| Spec sync and citation audit | Pass; no headings moved or citation updates required |
| Fresh adversarial code review | Pass; no must-fix, should-fix or nit |
| Live recall, false-positive, ranking and acceptance measurements | **Not run** |

Host report/fact-sheet and command-trace goldens are unchanged. The client's optional
dedicated-token wording alternative was not applied; the frozen wording passes.
Unit/fake-server evidence is not a live recall measurement.

The fresh reviewer independently reran `TestAssessmentCredential`,
`TestGitHubInventoryRunAndPrincipalResume` and
`TestMarkedPrincipalAndScopesCannotEstablishAuthority` in the collector, report
and gate packages with `-count=1`; all pass. It reviewed the raw/redacted response
boundary, resume gaps, schema and body trust, reporting no confirmed defect and
making no repository changes. This incremental review covers interactions with E5;
unchanged implementation relies on the recorded whole-E5 and collector-cleanup
reviews. All recorded offline checks and reviews pass. No release acceptance or
live measurement is inferred from those passes.

## Evaluation prerequisite and next measurement

No E3 preimplementation rest-lab seal is recorded. That prerequisite is not
established; a later seal cannot establish preimplementation blindness. This
record does not waive the prerequisite or claim E5 release acceptance.

A later evaluation requires these concrete preparations:

1. Name the owner and separately authorize a team-owned lab, its targets, reads
   and credential handling. No real lab targets or usable credentials are supplied
   by this implementation task; no live assessment runs here.
2. Use fresh independent seeder and ranker sessions following their role contracts.
   They never read collector code, rules or fixtures. The ranker sees no scheck
   output before ranking. An implementing session cannot perform these blind roles.
3. Keep seeded and clean labels outside implementers' readable access, publish
   their seal hash and identify the seeder, ranker and models where exposed.
   Freeze the clean-variant false-positive target before runs, resolving the target
   required by E3 rather than inventing an acceptance threshold in this record.
   Include issues outside planned checks and record them. Later labels establish
   only a postimplementation independent evaluation.
4. Record full seeded, clean, context-present/context-absent and missing-credential
   runs. Inspect audit logs for scope, GET-only API contact, read-only mirror access
   and secrecy. Record every recall miss before adding a fix; count clean false
   positives, compare the independent top five with the report, and check coverage
   marks/reasons and required exit 2 for an unassessed declared root.
5. Append results and owner handling of the unmet preimplementation prerequisite
   to the release acceptance evidence. Neither offline software tests nor a later
   independent evaluation silently satisfies that prerequisite.

Live recall, false positives, ranking and acceptance measurements are **not run**.
App grants/installation-principal support and runner access remain deferred with
no assigned later slice; this decision adds none of them. The unrelated operator
`.gitignore` edit is outside this change.

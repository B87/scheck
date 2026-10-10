# E6 gate-foundation authentication definition

Recorded 2026-10-10 on `e6-workspace-collector`. The AI Codex security-consultant
subagent `e6_auth_define` approved the targeted step-1 authentication contract before
implementation. Its exact model identifier was not exposed. This supplements
[e6-definition-2026-10-10.md](e6-definition-2026-10-10.md); it does not rewrite that
record or claim independent human approval, software-test success or acceptance.

The approved contract is recorded in
[workspace-collector.md](../spec/workspace-collector.md), “Boundary”, “Credential
files and profiles”, “Tenant binding and scope” and “Principal and resume”:

- Restricted `authorized_user` and delegated `service_account` credential files,
  fixed profiles, strict size/JSON/field checks, and no discovery chain or process.
- In-process RSA JWT assertions with a literal token audience and bounded lifetime;
  the declared credential exchange goes through `Send`, with no arbitrary `POST`,
  no retry and no secret body or response in persisted evidence or audit output.
- Ordered private customer, domain and alias bootstrap, requiring usable evidence
  and exact verified-root binding before tenant reads; an alias needs a verified
  parent in the same returned domain set.
- Customer binding does not identify the caller. Step 1 never reuses Workspace
  evidence; current exclusion admission and delegated-user verification remain
  step-2 work.

The implementing session keeps the foundation library separate from engagement
stage/CLI integration. No live Workspace request or metric is recorded here.
Independent seeding, sealing, ranking, measurements and release acceptance remain
pending. This record does not repair or waive the missed historical E3 seal.

## Implementation review corrections

The AI security-consultant REVIEW required corrections to the initial implementation:
optional profile selection must not put OAuth-security or Gmail scopes into the
baseline bootstrap assertion, and every present allowed credential field must be a
string rather than accepting JSON `null`. The implementing session applied both:
all profiles use baseline Directory scopes for bootstrap, optional token attempts
remain steps 5/6, and present null fields are refused. A null token-response scope
remains unknown rather than an observed empty grant set.

The contract also records an immutable credential-file snapshot per gate session;
file changes take effect in a new session, while changed profile or delegated subject
stops current dependent requests. Client wording advice informed execution diagnostics
without claiming completed report review for the future CLI integration. This section
records required corrections and their implementation, not a final passing review,
test result, live measurement or acceptance.

## Follow-up targeted review

The implementing session reports that AI security-consultant `e6_auth_define` ran a
follow-up REVIEW after the required corrections and passed the targeted step-1
contract, with no remaining security-definition blocker. Exact model identity was
not exposed. Visible credential diagnostics use plain credential wording. Private
transport failures discard URL-bearing transport text, bootstrap audit URLs are
sanitized before later refusal, and recognized OAuth error codes yield fixed safe
messages without returned descriptions. Target GETs retain standard gate retries;
token POSTs never retry.

This is a targeted definition review, not the fresh adversarial code review. Full
checks are still running at this record's preparation; no test-pass result, live
measurement, full client report review or release acceptance is claimed.

## Completed step-1 software verification

The implementing session subsequently reports completed offline verification:

| Verification | Result and attribution |
|---|---|
| `make check` | Green: vet, `go fix`, lint with zero issues, dependency checks and the full race-test suite; local log `/tmp/scheck-e6-step1-check.log` |
| Focused fake-Google tests | Passed; no live Workspace API or real tenant was used |
| Fresh adversarial code review | AI Codex subagent `e6_foundation_code_review` reviewed the full uncommitted step-1 change against step-0 commit `4f61e6b`; no must-fix, should-fix or nit findings; reviewer made no edits |
| Targeted consultant follow-up | Passed as recorded above; client execution-diagnostic wording advice incorporated |

Exact reviewer model identifiers were not exposed. No review findings were deferred.
Step 1 is complete as a library. Tenant inventory, organizational-unit exclusion
admission, delegated-user verification and CLI/stage wiring remain step-2 work.
Full client report review awaits that integration. These software and AI-role review
results do not establish independent security assessment, live measurement, blind
recall, false-positive or ranking performance, or release acceptance. The historical
E3 seal gap and independent evaluation prerequisites remain unchanged.

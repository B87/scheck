# E6 Workspace definition and evaluation prerequisites

Recorded 2026-10-10 on `e6-workspace-collector`, before Workspace implementation.
This is a design and prerequisite record, not a security assessment, measurement or
release acceptance. The specification is
[workspace-collector.md](../spec/workspace-collector.md); the build sequence is
[ROADMAP.md, E6](../ROADMAP.md#e6--google-workspace-collector).

## Definition evidence

The implementing session reports these reviews of the E6 design:

| Review | Result and attribution |
|---|---|
| Security-consultant DEFINE and final REVIEW | Completed by the AI Codex subagent `e6_define`; the final review's enforcement/enrollment distinction and explicit optional group read were incorporated |
| Client REPORT wording review | Completed by the AI Codex subagent `e6_client_wording`, playing Brightcart/Dani; wording corrections distinguish observed flags from policy, retained assignments from usable access, and optional reads from baseline requirements |
| Spec-steward DRAFT and citation audit | Completed by the AI Codex subagent `e6_spec_draft`; the Workspace spec and related roadmap, scope, engagement and document references were synchronized |

The exact model identifiers are not exposed in this session. These AI role reviews
are not independent human consultant approval or blind lab evidence. They freeze
the intended read surface, rule outcomes, severity and coverage; fake-server proofs,
implementation review and all live measurements remain separate work. Targeted
authentication and parser DEFINE reviews precede implementation steps 1 and 3.

No Workspace collector code, live Workspace request or new lab labels were produced
by step 0. No recall, false-positive or ranking result is claimed.

## Unmet historical prerequisite

E3 requires the rest-lab labels, including Workspace and GitHub, to be sealed before
the first E5 or E6 implementation commit, whichever comes first. No such seal was
established before E5; only the domain-part seal is recorded. This is the same gap
recorded in
[e5-credential-decision-2026-10-10.md](e5-credential-decision-2026-10-10.md).
A later E6 seal cannot repair that missed deadline, establish earlier blindness or
waive the release gate. Historical evaluation records remain unchanged.

## Pending independent preparation

An independent E6 evaluation is still pending. It requires a separately authorized,
team-owned Workspace lab and these preparations before measured runs:

1. Name the lab owner and authorize its targets, reads and credential handling. This
   implementation task supplies neither live targets nor usable credentials and
   does not authorize changing a tenant to seed it.
2. Use independent seeder and ranker sessions under the roadmap and role contracts.
   They do not read collector code, rules or fixtures; the ranker does not see scheck
   output before ranking. Neither role runs inside this implementing session or its
   subagents.
3. Keep seeded and clean labels outside implementers' readable access. Publish only
   the seal hash and identify the seeder, ranker and models where exposed. Freeze
   the false-positive target required by E3 before runs, and include issues outside
   the planned checks. Do not invent an acceptance threshold in this record.
4. Record seeded, clean, context-present/context-absent and missing-credential runs
   separately. Review scope, declared read operations, the confined credential
   exchange, exclusions, secrecy, coverage and incomplete execution in the audits.
   Record each miss before a fix and compare the independent ranking with the report.
5. Append the measured results and owner handling of the unmet historical
   prerequisite to release evidence. A new pre-E6 seal establishes only the timing
   of that separate E6 evaluation; it does not satisfy the original pre-E5 deadline.

Independent seeding, sealing, ranking, live recall, false-positive measurements and
release acceptance are **not run**. Step 0 closes the definition and recording work;
it does not close these evaluation prerequisites.

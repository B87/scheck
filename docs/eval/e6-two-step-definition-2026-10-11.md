# E6 observed 2-step verification definition

Recorded 2026-10-11 on `e6-workspace-collector`, after step-3 commit `c69728e`. An
AI security-consultant subagent supplied the targeted step-4 DEFINE contract before
implementation; its exact model identifier was not given to the document editor.
This supplements [e6-definition-2026-10-10.md](e6-definition-2026-10-10.md) and
[e6-identity-definition-2026-10-10.md](e6-identity-definition-2026-10-10.md); it never
rewrites them or claims independent human approval, software-test success or
acceptance. Where the implementation differs, the difference is recorded in
[e6-two-step-verification-2026-10-11.md](e6-two-step-verification-2026-10-11.md).

## Verdict

The proposal was sound and matched the frozen spec; no blocking design error for
step 4. Three corrections were required before building: the possible-grace note was
inaccurate, the unit finding hid the enrollment breakdown, and malformed flag values
needed a rule. One release blocker outside step 4 was raised: a federated tenant
(Okta, Entra) declaring `everyone` can get a false critical.

## Approved step-4 contract

**`workspace.two_step_not_enforced`** (high, identity, not an exposure, subject
`org_unit`):

1. Group by each account's direct `orgUnitPath`; no subtree inheritance is claimed.
   The subject key is the lowercased canonical path and the label the observed path.
   Paths equal once lowercased in the unit tree may fire, are never disproved, and get
   a diagnostic note. An account path not in the unit tree fires under the observed
   path with "unit not found in the unit list" and is never disproved. A missing or
   empty unit path joins no unit.
2. Fires on an explicit `isEnforcedIn2Sv:false` on a known-active account; fire wins
   over abstention inside a unit, with "at least N" when unknowns or a partial
   population are present. Details carry the affected count, active accounts observed,
   enrollment among the affected (not enrolled, enrolled, unknown), unknown
   enforcement and population completeness. Listed order is not enrolled, enrolled,
   unknown, alphabetical within each.
3. Disproved only on a complete users population (any drop, including exclusion drops
   the gate accepts for admission, prevents disproval, per `spec/scope.md`), a unit in
   the tree and unambiguous, every account's activity known, every active account
   explicitly `true`, and no 2-step or step-3 security conflict. Narrowing this to
   units outside excluded subtrees is a possible later refinement.
4. Abstains otherwise.
5. Units with no accounts or only inactive accounts produce no judgment. An empty or
   failed users read gives an asset-level abstention, as does a complete nonempty
   population with no active account.
6. No exemptions: service, break-glass and new accounts are judged.
7. A list/detail difference on either 2-step flag makes only the 2-step rules unknown
   for that account; a step-3 security conflict also does. A present null or
   non-boolean flag is unknown. A malformed or rejected fresh detail must not fall
   back to the list value. A detail with a changed unit, refused by the gate, leaves
   the account unknown in both units.

**`workspace.admin_without_two_step`** (high, identity, not an exposure, subject
`account`):

8. Fires for a known-active admin (`isAdmin:true` or a supported privileged delegate)
   with explicit `isEnrolledIn2Sv:false` and no conflict. Disproved by explicit
   enrollment `true` whatever the admin status, known inactivity, or admin status known
   false (`isAdmin:false` and complete direct/indirect assignment interpretation).
   Abstains otherwise.
9. Delegates take the same id and severity. Customer-wide or unit scope stays in the
   excerpt; unit-scoped grants are not lowered.
10. The excerpt names the privilege as step 3 does; super admins as "super
    administrator (isAdmin)".
11. An enforced but unenrolled admin fires, with the clause "Google requires 2-step
    verification for this account but reports it not yet enrolled; until it enrolls, a
    password alone may sign it in."
12. Never `contradiction` on this id.

**Declaration comparison:**

13. `everyone` raises every fired unit. `admins` raises only fired units with an
    affected `isAdmin:true` account without conflict; delegates do not count.
14. `some` raises only on a complete population with every activity known, no 2-step
    conflict, at least one active account and every active account explicitly off.
15. `none` raises nothing, with a note when the tenant does better. Matching notes
    appear only on complete populations with no unknowns; "better than declared" may
    appear on a partial population with "at least".
16. `unknown` gets a readout note.
17. A tenant with no `access.mfa` entry gets no contradiction but the readout note.
    Duplicate entries are refused by validation.
18. Federation (owner, E8; not step 4): keep the finding and the contradiction, attach
    the federation caveat to every raised instance, and before release bring the owner
    an E8 question, "Do people sign in to Google Workspace through another identity
    provider?", whose consumer stops the contradiction for non-super-admin accounts. A
    Cloud Identity SSO profile read is a 0.0.3 candidate.

**Notes and coverage:**

19. A limits note whenever 2-step evidence was read.
20. A possible-grace note in corrected wording, listing the accounts, "at least" on a
    partial population, including accounts of unknown admin status and excluding fired
    admins.
21. Coverage sub-item "Workspace 2-step verification (Google's enforcement and
    enrollment flags)", its limits always among its reasons even when assessed;
    "Workspace OAuth grants and domain-wide delegation" stays *not assessed* with
    `no_rule`.
22. Single sign-on: the rule still fires, never abstains, and the wording says what
    was not read.

**Wording:**

23. The fixed client paragraph follows the evidence on each fired instance. The
    excerpt states `isEnforcedIn2Sv: false` for N active accounts and "Enrollment, as
    Google reports it: N enrolled, N not enrolled, N unknown."

## Definition strings

`workspace.two_step_not_enforced`:

- Title: "Google does not currently require 2-step verification for these accounts"
- Impact: "For these accounts, a stolen, reused or guessed password may be enough to
  sign in unless the user has turned on 2-step verification themselves. That gives
  access to their mail and files and to password resets for other services. While
  Google does not require it, users can turn it off again, and new accounts in the
  same place may start without it."
- Remediation: "In the Admin console, open Security → Authentication → 2-step
  verification. Check which setting applies to these accounts' organizational unit or
  groups, and turn on enforcement with a short new-user enrollment period. Tell users
  before the enforcement date so nobody is locked out. Prefer security keys or
  passkeys for administrators and for people with access to production or customer
  data. If people sign in to Google through another identity provider, confirm it
  requires a second factor for these accounts. Run scheck again to confirm that Google
  reports them as required."

`workspace.admin_without_two_step`:

- Title: "An administrator has not enrolled in 2-step verification"
- Impact: "Anyone who gets this administrator's password, through phishing, reuse from
  another site's breach or malware on a laptop, can sign in and use its administrative
  privileges. Depending on the role, that means resetting other users' passwords and
  taking over their accounts or, for a super administrator, control of the whole
  organization, including locking you out of it."
- Remediation: "Have this administrator enroll in 2-step verification now, preferably
  with a security key or passkey. For a break-glass account, register two hardware
  keys and store them apart. If the role is not needed, remove it or suspend the
  account until it is enrolled. Then require 2-step verification for administrators in
  the Admin console (Security → Authentication → 2-step verification) so it cannot be
  turned off."

## Notes as defined

- N1 limits: "2-step verification checks read Google's current per-account enforcement
  and enrollment flags. Organizational-unit policy, grace periods, configuration
  groups, sign-in through another identity provider, verification methods, backup
  codes and phishing resistance were not assessed."
- N2 possible grace: "Google requires 2-step verification for N accounts that it
  reports as not yet enrolled: … Either they are still within an enrollment period,
  when a password alone signs them in, or the period has ended and Google will not let
  them sign in until they enroll. scheck cannot read which. Ask your Workspace
  administrator to check these accounts." ("at least N" when partial.)
- N3 undeclared or `unknown`: "Google reports N of M active accounts … not currently
  required to use 2-step verification." with "You answered that you do not know who
  must use it." or "You did not say who must use it for this tenant."; on a partial
  population "at least N active accounts …; M active accounts were observed and the
  list of users was incomplete."
- N4 matching: `none` "Google reports N active accounts currently required to use
  2-step verification, more than you declared." ("at least" when partial); `everyone`
  or `some`, complete and all enforced, "Google reports every active account currently
  required to use 2-step verification, as you declared." (`some`: better than
  declared); `admins`, complete, "Google reports every super administrator observed
  currently required to use 2-step verification, as you declared."
- N5 the federation caveat on every raised instance.

## Must not claim

Unit policy off or disabled, or its cause; grace state or length; enrolled as
protected, a method or phishing resistance; another identity provider's enforcement;
disproval as "fine" (only "Google reports every active account observed in this unit
as currently required"); "only", "all" or "none" on a partial population; missing,
null, malformed or conflicting values as on or off; backup codes read; enrollment
contradicting a declaration; no-findings wording that presents abstained or partial
2-step evidence as secure.

## To the owner and E9

1. The federation question (decision 18), decided with the pending critical-context
   decision (`ROADMAP.md`, E9).
2. "Fix these first" should collapse many unit instances into one line (E9).

No live tenant was contacted, no software test is recorded here, and no SEED or RANK
work ran.

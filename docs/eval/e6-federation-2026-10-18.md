# E6 federation: the owner's decision, the DEFINE and the reviews

Recorded 2026-10-18 on `e10-federation`. This is offline evidence only. `make check`
is green. No live tenant was contacted, no acceptance pass was run, nothing was
measured, and the 0.0.2 release gates have not passed. It supplements
[e6-two-step-definition-2026-10-11.md](e6-two-step-definition-2026-10-11.md), which
raised the release blocker below, and rewrites nothing.

## The owner's decision

On 2026-10-18 the owner decided to build option A of the E6 step 4 federation release
blocker: a federated tenant (Okta, Entra) that declares `everyone` can get a false
high-ranked `contradiction`, because Google does not require its own 2-step
verification for people who sign in elsewhere.

## The DEFINE

An AI security-consultant subagent (model `claude-opus-5-5`) defined option A before
implementation. It is not independent human approval.

- **Field.** `access.mfa[i].sign_in`, one of `google`, `another_provider`, `unknown`;
  Google Workspace only; no `mixed` value.
- **Raise rule per `enforced` value.** `everyone` with `another_provider` raises a
  fired unit only when its affected accounts include a known super admin. `some` never
  raises under `another_provider`, since every active account off is what a federated
  tenant looks like. `admins`, `none` and `unknown` are unchanged. Super admins keep the
  raise because they can still sign in to Google with a Google password.
- **Wording surfaces.** The Why, four caveats (one per answer, absent included), the
  stopped "Not checked" line, the delegated-admin line, the readout note, the Plan
  lines and the coverage limit.
- **Interview.** The `mfa_sign_in` question, asked after `mfa`. Consumer:
  `workspace.two_step_sign_in` (E6).
- **0.0.3 contract.** The Cloud Identity SSO profile read takes precedence over
  `sign_in`: a unit observed with no SSO profile re-raises whatever `sign_in` says.
- **Open live check.** Whether Google's mandatory 2-step verification for super admins
  shows in `isEnforcedIn2Sv`. If it does not, a super admin raise under
  `another_provider` could be false. Not decided; carried to the acceptance run.

## The client INTERVIEW pass

An AI agent played Brightcart, Ledgerly and Stackpilot from the profiles in
`.agents/clients/`. They are not real operators.

- First tries were "yes", "no" and "sso"; the question refuses all three.
- Brightcart answered `unknown`.
- Stackpilot disputed "super administrators sign in to Google directly". The wording
  became "can still sign in to Google with a Google password", the prompt gained the
  private-window "how to tell" line, and JumpCloud was dropped from the examples.
- The client noted that the new `mfa` line pushes an Okta company to `everyone`. That
  was kept as intended: with `another_provider`, only super admins keep the raise.

## The first adversarial code review

No must-fix. Three should-fix and two nits, all fixed with tests:

- the stopped line names affected super admins on a stopped unit (possible only under
  `some`) as not protected by the provider;
- it says when scheck could not tell whether accounts are super admins, names super
  admins whose requirement could not be read, and counts accounts whose current status
  was unknown;
- the readout note says "K of the S observed" on an incomplete user list and adds the
  unread-requirement count;
- `access.mfa[i].sign_in` is cited as declared evidence only when `enforced` is
  `everyone` or `some`;
- the interview's blank-answer line for `some` says that if Google requires 2-step
  verification for no active account, every unit will rank higher.

## Status

The re-review is recorded below. The
open live check, the 0.0.3 SSO read and acceptance remain open.

## Re-review, 2026-10-18

A fresh `code-reviewer` (AI agent, claude-opus-5-5) on the fixes above: no must-fix, two
should-fix and one nit, each reproduced with a temporary test it then deleted. All three
are fixed, with tests (`TestTwoStepSignInUnknownStates`, `TestSignInQuestion`):

- Under `some` with `another_provider` the stopped line said an account of unknown
  administrator status "would rank this higher", which nothing can. The could-not-judge
  sentence is now printed under `everyone` only.
- Some unknown states were missed or misattributed: an account with unknown
  administrator status and unknown flags or activity said nothing; a super admin of
  unknown activity was described as having unread flags; the readout said no active
  super admin was observed without mentioning one of unknown activity. The stopped
  line now names every account that might be an affected super admin but could not be
  judged (unknown administrator status, activity or 2-step flags, or a security
  conflict), and the readout counts super admins of unknown activity.
- Nit: the blank-answer line for `some` now says "if the list of users is complete and
  Google requires 2-step verification for no active account, every unit with an active
  account will rank higher".

The raise decision, verdicts, severity and the existing notes did not move. Offline
only; `make check` green; no live tenant; no acceptance.

## Final review, 2026-10-18

A third `code-reviewer` (AI agent, claude-opus-5-5), narrowed to the re-review's fixes,
enumerated 108 account states through `Judge` and found one should-fix: the stopped line
also named an account whose flags read as required and only its activity was unknown,
which can never rank the unit higher. Such an account is now left out, with a test. Two
nits fixed in wording: the readout bullet in `spec/workspace-collector.md` lists the
administrative-status sentence, and the `some` blank-answer line says "Google reports
every active account as not required". No must-fix in any of the three reviews.

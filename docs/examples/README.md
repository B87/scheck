# Engagement examples

Files to copy and run. Each one is a real engagement file: `scheck run FILE
--stop-after intake` validates it and contacts nothing. Replace the
placeholders (`yourlab.example`, `203.0.113.5`, the GitHub organization
`yourlab`) before a run that contacts anything.

A credential never goes in these files. Tokens and keys come from the
environment, named in the file that needs them. The schema, and a file that
shows every key, are in
[spec/engagement.md](../spec/engagement.md), "The file".

Omitted `defaults` are probe off, scan off, and throttle `5/s` with
concurrency 2. A host with no `profile` is `baseline`. This build rejects any
other probe or scan mode. A cloud root is accepted and not read: its collector
is 0.0.3, and the run exits 2. These files do not declare one.

| File | What it runs |
|---|---|
| [host.yaml](host.yaml) | One host over SSH. No network collector. |
| [domain.yaml](domain.yaml) | Domain, mail DNS and one site. No credential. |
| [github.yaml](github.yaml) | One GitHub organization. |
| [workspace.yaml](workspace.yaml) | Workspace directory: people, admins, 2-step verification. No mailbox sign-in. |
| [workspace-mail.yaml](workspace-mail.yaml) | That, plus Gmail forwarding settings. Needs a service account and `authorization.mailboxes`. |
| [first-engagement.yaml](first-engagement.yaml) | The four roots 0.0.2 reads, in one file. Setup stays in the single-surface files. |

Dates in a file are illustrations. A mailbox approval lasts at most 90 days;
replace `date` and `expires` with a current span before a mail run. A `left`
date the comment calls past has to be in the past in `engagement.timezone`.

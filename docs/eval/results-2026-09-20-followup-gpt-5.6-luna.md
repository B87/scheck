# Phase 2 evaluation — 2026-09-20T19:10:20Z

provider `openai-compatible`, model `gpt-5.6-luna`, prompt `sp-bb2762146136`, scheck `dev`, 3 repeat(s), 3 cases

## Arms

| arm | runs | correct | false positives | missed | abstentions | resolved follow-ups | incomplete | median latency | median tokens | cost |
|---|---|---|---|---|---|---|---|---|---|---|
| rules | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 9ms | 0 | n/a |
| single-pass | 9 | 0 | 0 | 3 | 0 | 0 | 0 | 1.994s | 9350 | $0.0036 |
| agent | 9 | 1 | 1 | 2 | 0 | 0 | 0 | 10.419s | 38860 | $0.0158 |

## Cases

| case | kind | arm | status | model findings | correct | fp | missed | resolved |
|---|---|---|---|---|---|---|---|---|
| linux-cron-fetch | follow-up | rules #1 | complete |  | 0 | 0 | 0 | false |
| linux-cron-fetch | follow-up | single-pass #1 | complete | privesc.sudo_nopasswd_broad | 0 | 0 | 1 | false |
| linux-cron-fetch | follow-up | single-pass #2 | complete | net.unexpected_listener | 0 | 0 | 1 | false |
| linux-cron-fetch | follow-up | single-pass #3 | complete | accounts.unexpected_admin | 0 | 0 | 1 | false |
| linux-cron-fetch | follow-up | agent #1 | complete | persist.unexpected_entry, privesc.sudo_nopasswd_broad | 1 | 0 | 0 | false |
| linux-cron-fetch | follow-up | agent #2 | complete | custom:ssh_root_without_password, persist.unexpected_entry, privesc.sudo_nopasswd_broad | 1 | 1 | 0 | false |
| linux-cron-fetch | follow-up | agent #3 | complete | custom:sshd_root_without_password, net.unexpected_listener, privesc.sudo_nopasswd_broad | 0 | 1 | 1 | false |
| linux-sshd-include | follow-up | rules #1 | complete |  | 0 | 0 | 0 | false |
| linux-sshd-include | follow-up | single-pass #1 | complete |  | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | single-pass #2 | complete | fw.no_firewall_active | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | single-pass #3 | complete | fw.no_firewall_active | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | agent #1 | complete | accounts.unexpected_admin, fw.no_firewall_active, net.unexpected_listener | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | agent #2 | complete | sshd.password_auth_exposed | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | agent #3 | complete | custom:journal-empty, fw.no_firewall_active, net.unexpected_listener | 0 | 1 | 1 | false |
| linux-unit-in-tmp | follow-up | rules #1 | complete |  | 0 | 0 | 0 | false |
| linux-unit-in-tmp | follow-up | single-pass #1 | complete |  | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | single-pass #2 | complete |  | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | single-pass #3 | complete |  | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | agent #1 | complete | net.unexpected_listener, persist.unexpected_entry | 1 | 0 | 0 | false |
| linux-unit-in-tmp | follow-up | agent #2 | complete | net.unexpected_listener | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | agent #3 | complete |  | 0 | 0 | 1 | false |

## Criteria (docs/eval/phase2-criteria.md)

- FAIL — §3.1 agent finds strictly more than single-pass, from ≥2 resolved follow-up cases (agent 1 vs single-pass 0 correct; 0 follow-up cases resolved)
- FAIL — §3.2 agent false positives not higher than single-pass (agent 1 vs single-pass 0)
- PASS — §3.3 agent missed issues not higher than single-pass (agent 2 vs single-pass 3)
- FAIL — §3.4 every correlated case found by the agent in the majority of runs (0 of 0)
- FAIL — §3.5 clean hosts: zero extra findings in the majority of runs (0 of 0)
- FAIL — §3.7 median clean-host agent cost under $0.50 and latency under 5m (cost unknown (unpriced provider), median latency 10.419s)

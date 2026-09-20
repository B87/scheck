# Phase 2 evaluation — 2026-09-20T19:12:09Z

provider `openai-compatible`, model `gpt-5.6-terra`, prompt `sp-bb2762146136`, scheck `dev`, 3 repeat(s), 3 cases

## Arms

| arm | runs | correct | false positives | missed | abstentions | resolved follow-ups | incomplete | median latency | median tokens | cost |
|---|---|---|---|---|---|---|---|---|---|---|
| rules | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 9ms | 0 | n/a |
| single-pass | 9 | 0 | 0 | 3 | 0 | 0 | 0 | 4.092s | 9519 | $0.0973 |
| agent | 9 | 0 | 0 | 3 | 0 | 0 | 0 | 4.099s | 9512 | $0.0534 |

## Cases

| case | kind | arm | status | model findings | correct | fp | missed | resolved |
|---|---|---|---|---|---|---|---|---|
| linux-cron-fetch | follow-up | rules #1 | complete |  | 0 | 0 | 0 | false |
| linux-cron-fetch | follow-up | single-pass #1 | complete |  | 0 | 0 | 1 | false |
| linux-cron-fetch | follow-up | single-pass #2 | complete |  | 0 | 0 | 1 | false |
| linux-cron-fetch | follow-up | single-pass #3 | complete |  | 0 | 0 | 1 | false |
| linux-cron-fetch | follow-up | agent #1 | complete |  | 0 | 0 | 1 | false |
| linux-cron-fetch | follow-up | agent #2 | complete |  | 0 | 0 | 1 | false |
| linux-cron-fetch | follow-up | agent #3 | complete |  | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | rules #1 | complete |  | 0 | 0 | 0 | false |
| linux-sshd-include | follow-up | single-pass #1 | complete |  | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | single-pass #2 | complete |  | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | single-pass #3 | complete |  | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | agent #1 | complete |  | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | agent #2 | complete |  | 0 | 0 | 1 | false |
| linux-sshd-include | follow-up | agent #3 | complete |  | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | rules #1 | complete |  | 0 | 0 | 0 | false |
| linux-unit-in-tmp | follow-up | single-pass #1 | complete |  | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | single-pass #2 | complete |  | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | single-pass #3 | complete |  | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | agent #1 | complete |  | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | agent #2 | complete |  | 0 | 0 | 1 | false |
| linux-unit-in-tmp | follow-up | agent #3 | complete |  | 0 | 0 | 1 | false |

## Criteria (docs/eval/phase2-criteria.md)

- FAIL — §3.1 agent finds strictly more than single-pass, from ≥2 resolved follow-up cases (agent 0 vs single-pass 0 correct; 0 follow-up cases resolved)
- PASS — §3.2 agent false positives not higher than single-pass (agent 0 vs single-pass 0)
- PASS — §3.3 agent missed issues not higher than single-pass (agent 3 vs single-pass 3)
- FAIL — §3.4 every correlated case found by the agent in the majority of runs (0 of 0)
- FAIL — §3.5 clean hosts: zero extra findings in the majority of runs (0 of 0)
- FAIL — §3.7 median clean-host agent cost under $0.50 and latency under 5m (cost unknown (unpriced provider), median latency 4.099s)

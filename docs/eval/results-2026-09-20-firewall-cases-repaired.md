# Phase 2 evaluation — 2026-09-20T19:55:58Z

provider `openai-compatible`, model `gpt-5.6-luna`, prompt `sp-e0d904499422`, scheck `dev`, 3 repeat(s), 2 cases

## Arms

| arm | runs | correct | false positives | missed | abstentions | resolved follow-ups | incomplete | median latency | median tokens | cost |
|---|---|---|---|---|---|---|---|---|---|---|
| rules | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 13ms | 0 | n/a |
| single-pass | 6 | 0 | 0 | 1 | 1 | 0 | 0 | 7.185s | 10472 | $0.0081 |
| agent | 6 | 1 | 0 | 0 | 1 | 0 | 0 | 16.871s | 47604 | $0.0271 |

## Cases

| case | kind | arm | status | model findings | correct | fp | missed | resolved |
|---|---|---|---|---|---|---|---|---|
| linux-no-firewall | correlated | rules #1 | complete |  | 0 | 0 | 0 | false |
| linux-no-firewall | correlated | single-pass #1 | complete |  | 0 | 0 | 1 | false |
| linux-no-firewall | correlated | single-pass #2 | complete |  | 0 | 0 | 1 | false |
| linux-no-firewall | correlated | single-pass #3 | complete |  | 0 | 0 | 1 | false |
| linux-no-firewall | correlated | agent #1 | complete | fw.no_firewall_active | 1 | 0 | 0 | false |
| linux-no-firewall | correlated | agent #2 | complete | fw.no_firewall_active | 1 | 0 | 0 | false |
| linux-no-firewall | correlated | agent #3 | complete | fw.no_firewall_active | 1 | 0 | 0 | false |
| linux-unavailable-firewall | misleading | rules #1 | complete |  | 0 | 0 | 0 | false |
| linux-unavailable-firewall | misleading | single-pass #1 | complete |  | 0 | 0 | 0 | false |
| linux-unavailable-firewall | misleading | single-pass #2 | complete |  | 0 | 0 | 0 | false |
| linux-unavailable-firewall | misleading | single-pass #3 | complete |  | 0 | 0 | 0 | false |
| linux-unavailable-firewall | misleading | agent #1 | complete |  | 0 | 0 | 0 | false |
| linux-unavailable-firewall | misleading | agent #2 | complete |  | 0 | 0 | 0 | false |
| linux-unavailable-firewall | misleading | agent #3 | complete | fw.no_firewall_active | 0 | 1 | 0 | false |

## Criteria (docs/eval/phase2-criteria.md)

- FAIL — §3.1 agent finds strictly more than single-pass, from ≥2 resolved follow-up cases (agent 1 vs single-pass 0 correct; 0 follow-up cases resolved)
- PASS — §3.2 agent false positives not higher than single-pass (agent 0 vs single-pass 0)
- PASS — §3.3 agent missed issues not higher than single-pass (agent 0 vs single-pass 1)
- PASS — §3.4 every correlated case found by the agent in the majority of runs (1 of 1)
- FAIL — §3.5 clean hosts: zero extra findings in the majority of runs (0 of 0)
- FAIL — §3.7 median clean-host agent cost under $0.50 and latency under 5m (cost unknown (unpriced provider), median latency 16.871s)

# Injection corpus

`hostile/` holds operator prose that carries instruction-shaped text (docs/SPEC.md §11):
override the role, report nothing, downgrade or accept findings, run a command, fetch a
URL, read a sensitive path, fabricate evidence, imitate the structured schema in prose.
`benign/` holds one control per hostile file, with the same name, that differs only in
not carrying the injection.

The mock-driven tests in `internal/agent` prove the boundaries a scripted model cannot
cross: prose never reaches the grader, rule findings cannot be suppressed, and a hostile
tool call is denied and audited. They do not prove that a model resists the text;
`docs/eval/phase2-criteria.md` §4 says what the real-model evaluation (M2.7) must show
over these pairs before 0.0.1.

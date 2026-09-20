# scheck — optional research roadmap

**Status (2026-09-20):** proposed experimental work, deferred from 0.0.1. No product
release version or delivery date is assigned. No slice below is marked implemented.

## Scope and relationship to releases

This track explores bounded assessment under [SPEC.md §5.9](SPEC.md). It is independent
of the product sequence: [0.0.1](ROADMAP-0.0.1.md), [0.0.2](ROADMAP-0.0.2.md),
[0.0.3](ROADMAP-0.0.3.md) and tentative [0.0.4](ROADMAP-0.0.4.md).
No ordinary audit, default CI job or product release gate depends on this experiment.

The existing design records Jev access as waitlisted; verify access before R3 rather
than assuming availability. R1 can run offline when research is prioritized after the
first release. Do not scaffold an empty production abstraction while waiting for access.
A negative result is a valid completed research outcome. Assign any proposed production
integration to a future release only after R4 establishes its value and scope.

M2.7's real-model quality evaluation and the adversarial tests for shipped AI remain
mandatory in 0.0.1. They validate the production approach; this track explores an
alternative and cannot replace those release checks.

## Research slices

### R1 — labeled fixtures and offline assessment harness
Start after M1 facts are available; this does not gate M2. Build a small fixture corpus
for service/context relationships (`expected`, `unexpected`, `insufficient_context`),
with human labels and evidence references. Include absent context, unavailable checks,
truncation, contradictions and instruction-shaped content. Separate development cases
from held-out evaluation cases. Use authored synthetic responses to exercise the harness;
neither an API key nor a vendor capture is needed to create them.
**Demo:** an offline test runs fixture facts plus context through scripted assessments
and writes a separate evaluation artifact without changing the normal report.
**Done when:** evidence references and result shapes are validated; missing/invalid
answers and uncertainty leave normal findings, severity and exit codes unchanged.
Synthetic responses are clearly labeled; passing tests makes no model-quality claim.
**Spec:** §5.9.

### R2 — optional comparison with an available model
Once an existing generative/local adapter is usable, evaluate the same labeled cases
through it and compare with deterministic rules. Use this to improve task definitions
and the measurement harness, without claiming it simulates Jev's calibration or accuracy.
If no model is available, R1 still completes and mainline development continues.
**Demo:** an opt-in evaluation records model/question versions, per-case predictions,
precision/recall, false negatives, abstentions, latency and cost where available.
**Done when:** quality measurements are distinguishable from scripted plumbing tests;
no comparison run is required in default CI. Freeze evaluation criteria before R3.
**Spec:** §5.9.

### R3 — Jev adapter and live evaluation, deferred until access
Only when credentials are available, add a small Go HTTP adapter inside the experiment.
Use a local fake server for request/response validation, authentication failures,
rate limits, overload, timeouts and malformed responses. Enforce egress policy before
requests, bounded retries, and environment-only credentials. Pin model/question versions.
**Demo:** an explicitly enabled live run compares actual Jev against R2 and deterministic
baselines on the held-out cases, including hostile and incomplete evidence.
**Done when:** actual measurements establish whether accuracy, investigation effort and
cost/latency justify adoption. No arbitrary confidence threshold is treated as calibrated.
Access unavailable means this slice stays deferred; it does not block any product release.
**Spec:** §5.9.

### R4 — decide whether to integrate
Write an evidence-backed decision: keep the experiment, remove it, or propose a bounded
production role with explicit fallback and coverage semantics. Any production integration
requires updating the spec, reporting contract and tests first. Do not silently promote
an experimental assessment into a finding filter or an investigation gate.
**Done when:** the decision cites actual evaluation results; no integration is required
for a successful experiment or for shipping a product release.
**Spec:** §5.9.


## Completion evidence

- Preserve labeled fixtures, evaluation criteria, model/question versions and measured
  results separately from normal reports.
- Keep synthetic plumbing tests distinguishable from real-model evaluation.
- R4 records a decision to retain, remove or propose integration of the experiment,
  with costs, uncertainty and limitations supported by results.
- An unavailable vendor leaves R3 deferred, without delaying a product release or
  implying that a synthetic comparison validated that vendor.

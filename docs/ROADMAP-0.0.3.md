# scheck — roadmap to 0.0.3

**Status (2026-09-20):** planned. This release expands inference compatibility after
0.0.2's application check packs. No slice below is marked implemented.

## Release scope

- **0.0.1:** reliable core assessment and evaluated AI; see [ROADMAP-0.0.1.md](ROADMAP-0.0.1.md).
- **0.0.2:** reviewed check packs and application coverage; see
  [ROADMAP-0.0.2.md](ROADMAP-0.0.2.md).
- **0.0.3:** M3 — additional providers, tool-call emulation and local-only inference,
  with small-context chunking subject to demonstrated need and quality evaluation.

Operational features are tentatively assigned to [0.0.4](ROADMAP-0.0.4.md).
Optional bounded assessment lives in the [research roadmap](ROADMAP-RESEARCH.md),
with no promised shipping version or dependency on this release. That track's ordering
decision names this release as the candidate home *if* its R4 gate ever recommends
integration, because the inference contract lives here; that is a candidacy, not a
commitment, and nothing in this release plan depends on it.

Historical M3 slice IDs are preserved even though M5 ships first. Product release
numbers are separate from the report's `schema_version`.

`SPEC.md` §5 supplies the deferred provider design. Update it alongside implementation
where evidence requires a design change. New providers operate on the same facts and
pack contributions, through the existing tool, policy, grading and report contracts.

## Shared requirements

- Preserve one provider-neutral agent loop and the existing runner enforcement path.
  Provider SDK types and emulation stay inside the inference layer.
- Every request passes the 0.0.1 full-request context guard, including output reservation
  and provider framing. Chunking does not replace guards or increase shared budgets.
- Overflow preserves evidence and findings, reports an incomplete assessment and exits
  2. No silent evidence removal or hosted fallback from a local-only run.
- Mock conformance tests prove software behavior. Newly supported inference paths need
  repeated real-model quality and adversarial evaluations, with criteria fixed before
  evaluation and model/prompt versions recorded.
- Existing check-pack provenance, report compatibility, grading, redaction and read-only
  guarantees apply across providers. Run `make check` before implementation commits.

## M3 — additional providers and small-context support

Goal: extend inference compatibility while preserving one agent loop, one tool surface
and the same reporting and security contracts.

### M3.1 — Anthropic provider

Deliver an `anthropic` adapter with native tool calling and mappings for supported
reasoning effort and cache hints. Verify current provider behavior during implementation;
model names and API details are not frozen by this roadmap. Document the supported
endpoint/authentication combinations; do not claim cloud-platform support without tests.

**Demo:** assess the same fixture host used in the 0.0.1 evaluation with
`openai-compatible` and `anthropic`, producing schema-valid reports from both.

**Done when:** the common provider conformance suite passes; SDK types stay inside
`llm`; cache and effort mappings are exercised and reported honestly in `Native`;
context accounting includes provider framing; repeated quality and adversarial runs
are recorded. Different findings are permitted; evidence and grading contracts are not.
Any necessary interface change is justified in the spec rather than hidden in agent code.

**Spec:** §5.1, §5.2, §5.5, §11.

### M3.2 — Ollama and tool-call emulation

Deliver the `ollama` adapter and an adapter-owned tool-call protocol for models without
native tool calling. Use native features when available and record emulation honestly.
The agent still receives the same normalized tool calls and results.

**Demo:** run against a local model without native tool calling and show validated
findings with `native.tool_calling: false` and the code-enforced confidence cap.
The combined `--local-only` demo depends on M3.3.

**Done when:** the same conformance suite passes without conditional skips; malformed
or ambiguous model text never becomes unchecked execution; protocol errors, truncation
and refusals have tested outcomes; emulated findings are capped at medium confidence
by code. Repeated real-model evaluations cover both ordinary and hostile evidence.
No provider-name or native-capability branches appear in the agent loop.

**Spec:** §5.3, §5.5, §11.

### M3.3 — local-only inference and egress control

Deliver `--local-only` and `allow_egress: false` as enforced inference restrictions.
Reject non-local inference providers before contacting them. Define and test local
endpoint validation, redirects and fallback behavior; a provider name or loopback URL
alone is not proof that the full inference path stays local.

The guarantee concerns inference egress. An explicitly selected SSH target still
requires its SSH connection; document this distinction and the startup ordering.
Do not silently switch from a local model to a hosted one on failure.

**Demo:** a local inference run succeeds; a hosted-provider selection with
`--local-only` fails with exit 3 before any inference network request.

**Done when:** dial-observing tests prove refusal without relying on packet capture;
the supported local deployment's egress assumptions are documented and verified;
endpoint and fallback cases are covered; both local and hosted runs produce reports
under the same schema. The existing facts-only offline path remains available.

**Spec:** §5.4, §8, §9.

### M3.4 — small-context chunking

Deliver domain-based fact-sheet chunking and a final correlation pass. Introduce
`Budgets.ChunkAtFraction` here, initially 0.5, to trigger chunking when the system
prefix exceeds that fraction of `Limits.MaxContext`. All requests still pass the
full-request guard and share the existing run budgets.

Do not assume findings alone are sufficient input to the correlation pass. Individually
unremarkable facts can jointly establish a finding. Define a bounded representation
that preserves the needed evidence and its references; mark incomplete coverage when
that evidence cannot fit rather than silently losing it.

**Demo:** a supported small-context model completes the labeled fixture suite through
chunking, including a finding requiring evidence from different domains.

**Done when:** repeated chunked and unchunked runs on the same large-context model
meet predefined quality criteria. Include cases where neither domain alone produces
a finding, incomplete evidence, hostile output and budget exhaustion. Record false
positives, missed issues, resolved uncertainty, latency and cost. One matching run is
not sufficient evidence that chunking preserves signal.

**Spec:** §4.4, §5.3, §11; extend the phase-2 evaluation from 0.0.1.

## Sequencing and release evidence

M3.1 (Anthropic) and M3.2 (Ollama/emulation) serve different users and can be developed
independently. M3.3 is required before claiming local-only inference support; its
successful local-run demo depends on a working local adapter. M3.4 depends on the
existing context guards and evaluation harness, not on adding every provider first.

Do not bundle all four slices merely because they share a milestone number. The default
0.0.3 scope is additional provider and local-only support (M3.1–M3.3). M3.4 is a candidate
for this release only when supported models need chunking and its evaluation passes.
If their context windows already fit the evidence within budget, explicitly defer
M3.4; honest overflow handling remains mandatory.

0.0.3 sign-off requires recorded evidence for each shipped path:

1. The common provider conformance suite passes, with schema-valid reports and accurate
   capability/usage metadata across supported adapters.
2. Repeated real-model quality and adversarial evaluations meet predefined criteria,
   including representative application-pack evidence from 0.0.2.
3. Egress-refusal tests and a documented, tested local-only deployment substantiate
   the local inference guarantee; SSH target connections are distinguished from inference.
4. If chunking ships, repeated comparisons preserve cross-domain signal and meet cost,
   latency and quality criteria. Fitting the request window alone is insufficient.
5. Existing security, redaction, coverage, pack provenance and read-only integration
   guarantees remain green, with `make check` and relevant integration results recorded.

If users cannot adopt 0.0.1 because of provider availability or data-egress restrictions,
revisit the release order explicitly and bring the necessary M3 slices forward.
Otherwise application coverage in 0.0.2 remains the priority. Failed evaluations require
an explicit scope decision, never weaker acceptance criteria or a false completion mark.

## Outside 0.0.3

- Runtime loading of arbitrary commands or executable plugins, a marketplace and
  automatic plugin updates.
- Provider-specific execution/policy paths or a second agent implementation.
- A promise that every model or endpoint is supported merely because its API is compatible.
- The optional bounded-assessment research track as a release dependency.

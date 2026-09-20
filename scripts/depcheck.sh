#!/bin/sh
# The packages that consume the llm contract must compile with no provider
# adapter and no provider SDK in their dependency graph (docs/SPEC.md §5.1).
# Run from the module root; exits 1 naming the offending edge.
set -eu
status=0
for pkg in agent policy check finding report llm; do
  dir="./internal/$pkg"
  [ -d "$dir" ] || continue
  deps=$(go list -deps "$dir" 2>/dev/null || true)
  bad=$(printf '%s\n' "$deps" | grep -E 'internal/llm/(mock|openai|all|conformance)|openai|anthropic' || true)
  if [ -n "$bad" ]; then
    echo "depcheck: internal/$pkg depends on a provider:" >&2
    printf '%s\n' "$bad" | sed 's/^/  /' >&2
    status=1
  fi
done
exit $status

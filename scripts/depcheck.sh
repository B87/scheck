#!/bin/sh
# The packages that consume the llm contract must compile with no provider
# adapter and no provider SDK in their dependency graph (docs/SPEC.md §5.1),
# and none of them may depend on the bounded assessment experiment, which is
# reachable from internal/eval alone (docs/SPEC.md §5.9).
# Run from the module root; exits 1 naming the offending edge.
set -eu
status=0
for pkg in agent policy check finding report llm bounded; do
  dir="./internal/$pkg"
  [ -d "$dir" ] || continue
  deps=$(go list -deps "$dir" 2>/dev/null || true)
  bad=$(printf '%s\n' "$deps" | grep -E 'internal/llm/(mock|openai|all|conformance)|openai|anthropic' || true)
  if [ -n "$bad" ]; then
    echo "depcheck: internal/$pkg depends on a provider:" >&2
    printf '%s\n' "$bad" | sed 's/^/  /' >&2
    status=1
  fi
  if [ "$pkg" != "bounded" ]; then
    experiment=$(printf '%s\n' "$deps" | grep -E 'internal/bounded$' || true)
    if [ -n "$experiment" ]; then
      echo "depcheck: internal/$pkg depends on the bounded experiment:" >&2
      printf '%s\n' "$experiment" | sed 's/^/  /' >&2
      status=1
    fi
  fi
done
exit $status

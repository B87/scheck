#!/bin/sh
# The packages that consume the llm contract must compile with no provider
# adapter and no provider SDK in their dependency graph (docs/spec/model.md §2),
# and none of them may depend on the bounded assessment experiment, which is
# reachable from internal/eval alone (docs/spec/bounded.md).
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
# The engagement and its collectors run on rules through 0.0.3: no model
# path in their dependency graph (AGENTS.md, "Layout"). Only the host asset
# imports the runner or a target; every other engagement package reaches a
# host through it. The rule is on direct imports, since the host catalog and
# the finding catalog themselves import target and runner.
pkgs=""
for tree in engagement collector; do
  if [ -d "./internal/$tree" ]; then
    pkgs="$pkgs $(go list "./internal/$tree/...")"
  fi
done
for pkg in $pkgs; do
  deps=$(go list -deps "$pkg")
  model=$(printf '%s\n' "$deps" | grep -E 'internal/(llm|agent|bounded)(/|$)' || true)
  if [ -n "$model" ]; then
    echo "depcheck: $pkg depends on the model path:" >&2
    printf '%s\n' "$model" | sed 's/^/  /' >&2
    status=1
  fi
  case "$pkg" in
  */internal/engagement/hostasset) ;;
  *)
    imports=$(go list -f '{{join .Imports "\n"}}' "$pkg")
    reach=$(printf '%s\n' "$imports" | grep -E 'internal/(runner|target)(/|$)' || true)
    if [ -n "$reach" ]; then
      echo "depcheck: $pkg imports the runner or a target; only internal/engagement/hostasset may:" >&2
      printf '%s\n' "$reach" | sed 's/^/  /' >&2
      status=1
    fi
    ;;
  esac
done
exit $status

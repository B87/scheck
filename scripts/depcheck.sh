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
# The scope gate is the one place a request for a web, domain or SaaS asset
# is sent (docs/spec/scope.md, "The scope gate"): no collector imports net or
# net/http, and none imports another collector; a fact one needs from
# another comes through a multi-fact rule in internal/engagement.
if [ -d ./internal/collector ]; then
  # What the gate, policy and the rules already bring in is allowed; whatever
  # else a collector pulls in, directly or through an SDK, may not reach the
  # network or a process, and may not come from outside the module and the
  # standard library. The graph is checked, not a list of names, so an SDK
  # that wraps net/http is caught.
  allowed=$(mktemp)
  go list -deps ./internal/engagement/gate ./internal/policy ./internal/finding | sort -u > "$allowed"
  for pkg in $(go list ./internal/collector/...); do
    extra=$(go list -deps "$pkg" | sort -u | comm -23 - "$allowed")
    bad=$(printf '%s\n' "$extra" | grep -E '^(net(/.*)?|crypto/tls|os/exec|syscall|unsafe|plugin|golang\.org/x/(net|sys|crypto/ssh)(/.*)?)$' |
      grep -vE '^net/(url|netip|mail)$' || true)
    foreign=$(printf '%s\n' "$extra" | grep -E '^[^/]+\.[^/]+/' | grep -v '^github.com/b87/scheck/' || true)
    if [ -n "$bad$foreign" ]; then
      echo "depcheck: $pkg reaches the network, a process or a third-party package outside the gate; only internal/engagement/gate sends requests:" >&2
      printf '%s\n' $bad $foreign | sort -u | sed 's/^/  /' >&2
      status=1
    fi
    other=$(go list -f '{{join .Imports "\n"}}' "$pkg" | grep -E 'internal/collector/' || true)
    if [ -n "$other" ]; then
      echo "depcheck: $pkg imports another collector:" >&2
      printf '%s\n' "$other" | sed 's/^/  /' >&2
      status=1
    fi
  done
  rm -f "$allowed"
fi
# Nothing is sent to the makers of scheck: no telemetry, no update check
# (docs/spec/engagement.md, "What left this machine"). The pin is on
# imports, read for every platform scheck ships for, since a file built
# only on one would otherwise escape the run on another; and on the calls
# made through the few packages allowed one of these imports for a narrow
# use.
goos_list='linux darwin'
listall() { # go list arguments, once per shipped GOOS
  for goos in $goos_list; do GOOS=$goos go list "$@"; done | sort -u
}
# First, every package outside the standard library and this module comes
# from a module on this list: a telemetry or HTTP SDK reaches the network
# through imports this check never sees, so adding a module is a change to
# this pin, reviewed as one. Which packages of golang.org/x/crypto may be
# imported is the second part's to say.
thirdparty='^(github\.com/spf13/(cobra|pflag)|gopkg\.in/yaml\.v3|golang\.org/x/(crypto|sys|term))(/|$)'
foreign=$(listall -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... | grep -vE '^github\.com/b87/scheck(/|$)' |
  grep -vE "$thirdparty" || true)
if [ -n "$foreign" ]; then
  echo "depcheck: a package from a module the no-telemetry pin does not list:" >&2
  printf '%s\n' "$foreign" | sed 's/^/  /' >&2
  status=1
fi
# Second, a package of this module imports an API that can dial, listen,
# resolve, send HTTP, run a process or make a raw system call, or a package
# of this module that does, only as its entry below allows: the scope gate,
# the SSH transport, the model adapters (built by internal/llm/all, and
# named by cmd/scheck for its flags) and the local target (which runs
# catalog entries, rule 2). cgo (import "C") is listed: a C call reaches the
# network with no Go import at all. Nothing but test code imports test/... cmd/scheck
# and the host asset import net only to split and join a host and port, and
# the run directory imports syscall only to lock itself, to open its files
# without following a link and to read who owns them and how many links
# they have; the token checks
# after this hold them to that. A model provider is built only by the
# hidden eval command and by `scheck providers`, whose construction does no
# I/O; the engagement's graph holds no model path (above), so `scheck run`
# reaches none.
risky='^(C|net|net/.*|crypto/tls|os/exec|syscall|unsafe|plugin|log/syslog|golang\.org/x/(net|sys|crypto)(/.*)?|github\.com/b87/scheck/(test/.*|internal/llm/[a-z]+))$'
allowed_import() {
  case "$1 $2" in
  *" net/url" | *" net/netip" | *" net/mail") return 0 ;;
  *" github.com/b87/scheck/internal/llm/all") return 0 ;;
  internal/engagement/gate\ net | internal/engagement/gate\ net/http | internal/engagement/gate\ crypto/tls | internal/engagement/gate\ syscall) return 0 ;;
  internal/target/ssh\ net | internal/target/ssh\ syscall | internal/target/ssh\ golang.org/x/crypto/ssh*) return 0 ;;
  internal/llm/*\ net/http | internal/llm/all\ github.com/b87/scheck/internal/llm/*) return 0 ;;
  internal/eval\ github.com/b87/scheck/internal/llm/mock) return 0 ;;
  cmd/scheck\ github.com/b87/scheck/internal/llm/openai) return 0 ;;
  internal/target/local\ os/exec) return 0 ;;
  cmd/scheck\ net | internal/engagement/hostasset\ net) return 0 ;;
  internal/engagement\ syscall) return 0 ;;
  test/*\ *) return 0 ;;
  esac
  return 1
}
reaching=$(listall -f '{{.ImportPath}}{{range .Imports}} {{.}}{{end}}' ./... | while read -r pkg imports; do
  pkg=${pkg#github.com/b87/scheck/}
  for i in $imports; do
    if printf '%s\n' "$i" | grep -qE "$risky" && ! allowed_import "$pkg" "$i"; then
      printf '%s %s\n' "$pkg" "$i"
    fi
  done
done | sort -u)
if [ -n "$reaching" ]; then
  echo "depcheck: only the gate, the SSH transport, the model adapters and the local target reach the network or a process:" >&2
  printf '%s\n' "$reaching" | sed 's/^/  /' >&2
  status=1
fi
# The token checks, over every file whatever its build tags: no alias or
# dot import that would hide a call, and no call beyond the allowed ones.
tokens() { # dir, import path, its name, allowed identifiers
  for f in $(grep -lE "^[[:space:]]*(import[[:space:]]+)?([A-Za-z_.][A-Za-z0-9_]*[[:space:]]+)?\"$2\"" "$1"/*.go 2>/dev/null | grep -v '_test\.go$'); do
    other=$(grep -E "^[[:space:]]+[A-Za-z_.][A-Za-z0-9_]*[[:space:]]+\"$2\"|^import[[:space:]]+[A-Za-z_.][A-Za-z0-9_]*[[:space:]]+\"$2\"" "$f" || true)
    calls=$(grep -oE "\\b$3\\.[A-Za-z_]+" "$f" | grep -vE "^$3\\.($4)\$" || true)
    if [ -n "$other$calls" ]; then
      echo "depcheck: $f uses $2 beyond $4:" >&2
      printf '%s\n%s\n' "$other" "$calls" | grep -v '^$' | sort -u | sed 's/^/  /' >&2
      status=1
    fi
  done
}
tokens cmd/scheck net net 'SplitHostPort|JoinHostPort'
tokens internal/engagement/hostasset net net 'SplitHostPort|JoinHostPort'
tokens internal/engagement syscall syscall 'Flock|LOCK_EX|LOCK_NB|LOCK_UN|EWOULDBLOCK|O_NOFOLLOW|Stat_t'
tokens cmd/scheck github.com/b87/scheck/internal/llm/openai openai 'Name|ResolveModel|DefaultModel'
# os starts a process without os/exec; only the local target runs one.
spawn=$(grep -rlE '\bos\.StartProcess\b' --include='*.go' cmd internal 2>/dev/null | grep -v '_test\.go$' || true)
if [ -n "$spawn" ]; then
  echo "depcheck: os.StartProcess outside the local target's os/exec:" >&2
  printf '%s\n' "$spawn" | sed 's/^/  /' >&2
  status=1
fi
# A model provider is built only by internal/llm's Build (Lookup returns
# no factory), and the adapters are registered process-wide: so any
# reference to Build, a call or a function value, is pinned wherever
# internal/llm is imported, never aliased, and made only by the hidden eval
# command and `scheck providers`.
llmimport='"github\.com/b87/scheck/internal/llm"'
importers=$(grep -rlE "$llmimport" --include='*.go' cmd internal 2>/dev/null | grep -v '_test\.go$' | grep -v '^internal/llm/' || true)
builders=""
for f in $importers; do
  if grep -qE "^[[:space:]]+[A-Za-z_.][A-Za-z0-9_]*[[:space:]]+$llmimport|^import[[:space:]]+[A-Za-z_.][A-Za-z0-9_]*[[:space:]]+$llmimport" "$f"; then
    builders="$builders $f(aliased)"
  fi
  case "$f" in
  cmd/scheck/evalcmd.go | cmd/scheck/providers.go) ;;
  *) if grep -qE '\bllm\.Build\b' "$f"; then builders="$builders $f"; fi ;;
  esac
done
if [ -n "$builders" ]; then
  echo "depcheck: a model provider is built outside the hidden eval command, or internal/llm is aliased:" >&2
  printf '%s\n' $builders | sed 's/^/  /' >&2
  status=1
fi
# Certificate verification is never turned off outside tests
# (docs/spec/scope.md, "Connections").
insecure=$(grep -rln --include='*.go' 'InsecureSkipVerify' cmd internal 2>/dev/null | grep -v '_test\.go$' || true)
if [ -n "$insecure" ]; then
  echo "depcheck: InsecureSkipVerify outside tests:" >&2
  printf '%s\n' "$insecure" | sed 's/^/  /' >&2
  status=1
fi
exit $status

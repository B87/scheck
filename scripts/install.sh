#!/bin/sh
# Download, verify and install a released scheck binary.
#
# The archive is never extracted before its SHA-256 has been compared against the
# release's checksums.txt, and there is no flag to skip that. A tool that inspects a
# host's security posture has no business being installed unverified.
#
#   sh install.sh                          # latest release, best install dir
#   sh install.sh --version v0.0.1         # a specific tag
#   sh install.sh --dir ~/bin              # a specific directory
#
# Environment equivalents: SCHECK_VERSION, SCHECK_INSTALL_DIR.

set -eu

REPO=B87/scheck
VERSION=${SCHECK_VERSION:-latest}
INSTALL_DIR=${SCHECK_INSTALL_DIR:-}

die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
	case $1 in
	--version) [ $# -ge 2 ] || die "--version needs a tag"; VERSION=$2; shift 2 ;;
	--version=*) VERSION=${1#--version=}; shift ;;
	--dir) [ $# -ge 2 ] || die "--dir needs a directory"; INSTALL_DIR=$2; shift 2 ;;
	--dir=*) INSTALL_DIR=${1#--dir=}; shift ;;
	-h | --help)
		cat >&2 <<'USAGE'
Download, verify and install a released scheck binary.

  install.sh                       latest release, best install directory
  install.sh --version v0.0.1      a specific tag
  install.sh --dir ~/bin           a specific directory

Environment equivalents: SCHECK_VERSION, SCHECK_INSTALL_DIR.
The archive's SHA-256 is always checked against the release's checksums.txt.
USAGE
		exit 0 ;;
	*) die "unknown argument: $1 (try --help)" ;;
	esac
done

# --- platform -------------------------------------------------------------

os=$(uname -s)
case $os in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported operating system: $os. scheck ships Linux and macOS binaries; build from source instead." ;;
esac

arch=$(uname -m)
case $arch in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture: $arch. scheck ships amd64 and arm64 binaries; build from source instead." ;;
esac

# --- tools ----------------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
	fetch_stdout() { curl -fsSL --retry 3 "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO "$2" "$1"; }
	fetch_stdout() { wget -qO- "$1"; }
else
	die "neither curl nor wget is available"
fi

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
	sha256() { openssl dgst -sha256 "$1" | sed 's/.*= *//'; }
else
	die "no SHA-256 tool found (sha256sum, shasum or openssl); refusing to install unverified"
fi

# --- resolve the tag ------------------------------------------------------

if [ "$VERSION" = latest ]; then
	# /releases/latest excludes drafts and prereleases.
	VERSION=$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" |
		sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$VERSION" ] || die "could not resolve the latest release tag; pass --version TAG"
fi
version=${VERSION#v} # archives are named without the leading v

archive="scheck_${version}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"

# --- install directory ----------------------------------------------------

if [ -z "$INSTALL_DIR" ]; then
	if [ -w /usr/local/bin ] 2>/dev/null; then
		INSTALL_DIR=/usr/local/bin
	else
		INSTALL_DIR=$HOME/.local/bin
	fi
fi
mkdir -p "$INSTALL_DIR" || die "cannot create $INSTALL_DIR"
[ -w "$INSTALL_DIR" ] || die "$INSTALL_DIR is not writable. Pass --dir DIR, or re-run this script with sudo."

# --- download and verify --------------------------------------------------

tmp=$(mktemp -d "${TMPDIR:-/tmp}/scheck-install.XXXXXX") || die "cannot create a temporary directory"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "scheck $VERSION ($os/$arch) -> $INSTALL_DIR"
say "downloading $archive"
fetch "$base/$archive" "$tmp/$archive" ||
	die "download failed: $base/$archive. Check that $VERSION exists and publishes a $os/$arch asset."
fetch "$base/checksums.txt" "$tmp/checksums.txt" || die "download failed: $base/checksums.txt"

expected=$(sed -n "s/^\([0-9a-f]\{64\}\)[ *]\{1,\}$archive\$/\1/p" "$tmp/checksums.txt" | head -n 1)
[ -n "$expected" ] || die "checksums.txt has no entry for $archive; refusing to install"
actual=$(sha256 "$tmp/$archive")
[ "$actual" = "$expected" ] || die "SHA-256 mismatch for $archive
  expected $expected
  actual   $actual
Do not use this download."
say "sha256 OK: $expected"

# --- extract and install --------------------------------------------------

tar -xzf "$tmp/$archive" -C "$tmp" scheck || die "the archive does not contain scheck"
chmod 0755 "$tmp/scheck"

# Install through a temporary name in the destination so a running scheck is
# replaced atomically and a failure never leaves a half-written binary on PATH.
staged="$INSTALL_DIR/.scheck.$$"
cp "$tmp/scheck" "$staged" || die "cannot write to $INSTALL_DIR"
mv -f "$staged" "$INSTALL_DIR/scheck" || { rm -f "$staged"; die "cannot install into $INSTALL_DIR"; }

say "installed $INSTALL_DIR/scheck"
"$INSTALL_DIR/scheck" --version >&2

case ":${PATH}:" in
*":$INSTALL_DIR:"*) ;;
*) say ""
   say "$INSTALL_DIR is not on your PATH. Add it, for example:"
   say "    export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

if [ "$os" = darwin ]; then
	say ""
	say "macOS binaries are unsigned and unnotarized. If Gatekeeper blocks it, allow it"
	say "in System Settings -> Privacy & Security after deciding to trust this download."
fi

say ""
say "Next: scheck local --no-persist    # facts + posture rules; no model, no key, free"
say "Exit 0 is not a security verdict; read the assessment coverage."

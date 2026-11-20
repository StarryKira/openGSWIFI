#!/bin/sh
#
# Installs the pinned release of cross (https://github.com/cross-rs/cross),
# the tool that runs cargo inside a container with the C toolchain of the
# target, into $CARGO_HOME/bin. The prebuilt static binary is checked against
# the SHA-256 below.
#
#   install-cross.sh
#
# Prebuilt for x86_64 Linux only (the CI runners). Anywhere else:
#   cargo install cross --version 0.2.5 --locked

set -eu

version=0.2.5
sha256=a486cefa6cb486971b97be321ea9dfc2e90c1979550295314a368f53fab6d588

bindir=${CARGO_HOME:-$HOME/.cargo}/bin

# (cross --version wants a Rust toolchain around; without one this just
# installs again.)
if [ -x "$bindir/cross" ] && "$bindir/cross" --version 2>/dev/null | grep -q "^cross $version\$"; then
	echo "install-cross: cross $version is already installed"
	exit 0
fi

case "$(uname -s)-$(uname -m)" in
Linux-x86_64) ;;
*)
	echo "install-cross: no pinned binary for $(uname -s) $(uname -m); run: cargo install cross --version $version --locked" >&2
	exit 1
	;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
f=cross-x86_64-unknown-linux-musl.tar.gz
curl -fsSL --retry 3 -o "$work/$f" "https://github.com/cross-rs/cross/releases/download/v$version/$f"
echo "$sha256  $work/$f" | sha256sum -c -
mkdir -p "$bindir"
tar -xzf "$work/$f" -C "$bindir" cross
echo "install-cross: cross $version installed in $bindir"

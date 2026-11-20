#!/bin/sh
#
# Writes every nftables ruleset gswifi-protect can generate into <outdir>, one
# <variant>.nft each, by running the nft_syntax integration test with
# GSWIFI_NFT_DUMP. ci/nft-check.sh then feeds them to the nft of an OpenWrt
# release.
#
#   nft-dump.sh <outdir>
#
# Where this machine has nft itself, the test also validates the rulesets with
# it, and "nft -c" has to talk to the kernel: the test binary is then run as
# root (through sudo if need be). It is built as the calling user first, so
# nothing in target/ ends up owned by root.

set -eu

out=${1:?usage: $0 <outdir>}
top=$(cd "$(dirname "$0")/.." && pwd)

mkdir -p "$out"
out=$(cd "$out" && pwd)
rm -f "$out"/*.nft

cd "$top"
exe=$(cargo test -p gswifi-protect --test nft_syntax --locked --no-run --message-format=json |
	sed -n 's/.*"executable":"\([^"]*[/\\]nft_syntax-[^"]*\)".*/\1/p' | tail -n 1)
[ -n "$exe" ] && [ -x "$exe" ] || { echo "nft-dump: cannot find the nft_syntax test binary" >&2; exit 1; }

as_root=
if [ "$(id -u)" != 0 ]; then
	for nft in /usr/sbin/nft /sbin/nft /usr/bin/nft; do
		[ -e "$nft" ] && as_root="sudo -n"
	done
fi
[ -z "$as_root" ] || echo "nft-dump: this machine has nft; running the test as root so that it can use it"

# The package directory, where cargo test would run it.
cd "$top/crates/gswifi-protect"
$as_root env GSWIFI_NFT_DUMP="$out" "$exe"
# Readable by the container user that checks them, whoever wrote them.
$as_root chmod -R a+rX "$out"

n=$(find "$out" -name '*.nft' | wc -l | tr -d ' ')
echo "nft-dump: $n rulesets in $out"
[ "$n" -gt 0 ] || { echo "nft-dump: the test wrote no rulesets" >&2; exit 1; }

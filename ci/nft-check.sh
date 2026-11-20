#!/bin/sh
#
# Checks every ruleset in <dir> (written by ci/nft-dump.sh) with the nft of
# the system this runs on: "nft -c -f" parses it and has the kernel validate
# it without loading anything. Meant for an OpenWrt rootfs container, which
# needs NET_ADMIN to talk to nf_tables:
#
#   docker run --rm --cap-add NET_ADMIN -v "$PWD/ci:/ci:ro" -v <dir>:/nft:ro \
#       openwrt:24.10.8 sh /ci/nft-check.sh /nft
#
# Exits non-zero when nft rejects any ruleset, or when there are fewer than
# NFT_MIN_RULESETS (default 14, what the nft_syntax test itself expects).

set -eu

dir=${1:?usage: $0 <dir>}
min=${NFT_MIN_RULESETS:-14}

command -v nft >/dev/null || { echo "FAIL: no nft on this system" >&2; exit 1; }
echo "$(nft --version) on $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}"), kernel $(uname -r)"

# Controls, so that a pass means something: nft must work here at all (it does
# not without NET_ADMIN or without nf_tables in the host kernel), and it must
# be able to say no.
if ! out=$(printf 'table inet gswifi_ci_probe\ndelete table inet gswifi_ci_probe\n' | nft -c -f - 2>&1); then
	echo "FAIL: nft cannot check even an empty table here:" >&2
	echo "$out" >&2
	echo "(the container needs --cap-add NET_ADMIN and a host kernel with nf_tables)" >&2
	exit 1
fi
if printf 'table inet gswifi_ci_probe { chain c { this is not nftables } }\n' | nft -c -f - >/dev/null 2>&1; then
	echo "FAIL: nft -c accepted a ruleset that is not valid" >&2
	exit 1
fi

n=0
bad=0
for f in "$dir"/*.nft; do
	[ -f "$f" ] || continue
	n=$((n + 1))
	if out=$(nft -c -f "$f" 2>&1); then
		echo "ok: ${f##*/}"
	else
		bad=$((bad + 1))
		echo "FAIL: ${f##*/}"
		echo "$out" | sed 's/^/    /'
	fi
done

echo "$n rulesets checked, $bad rejected"
[ "$n" -ge "$min" ] || { echo "FAIL: expected at least $min rulesets in $dir" >&2; exit 1; }
[ "$bad" -eq 0 ]

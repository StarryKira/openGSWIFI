#!/bin/sh
#
# Checks a release binary: it must be fully static (so that it runs on any
# router, whatever libc and libpcap that has), report the expected version and
# start. Prints its size.
#
#   check-binary.sh <binary> <cargo version> [runner]
#
# [runner] runs binaries of a foreign architecture, e.g. qemu-aarch64-static.
# Needs file(1) and readelf (binutils). In GitHub Actions the size also goes
# into the job summary, labelled $TARGET.

set -eu

bin=${1:?usage: $0 <binary> <cargo version> [runner]}
version=${2:?cargo version}
run=${3:-}

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

[ -f "$bin" ] || fail "$bin does not exist"

# -------------------------------------------------------------- static --

desc=$(file -b "$bin")
echo "$desc"
case "$desc" in
*"static-pie linked"*) linking=static-pie ;;
*"statically linked"*) linking=static ;;
*) fail "$bin is not statically linked" ;;
esac
# file(1) has been wrong about static-pie before; ask the ELF headers too.
if readelf -lW "$bin" | grep -q 'INTERP'; then
	fail "$bin asks for a program interpreter (dynamic loader)"
fi
if readelf -dW "$bin" 2>/dev/null | grep -q '(NEEDED)'; then
	fail "$bin needs shared libraries: $(readelf -dW "$bin" | grep '(NEEDED)' | tr -s ' ' | tr '\n' ';')"
fi
ok "$linking: no interpreter, no shared libraries"

case "$desc" in
*"not stripped"*) fail "$bin is not stripped" ;;
esac
ok "stripped"

# ----------------------------------------------------------------- run --

# $run is deliberately unquoted: it is empty for native binaries.
out=$($run "$bin" --version) || fail "$bin --version does not run"
[ "$out" = "gswifi $version" ] || fail "--version prints [$out], expected [gswifi $version]"
ok "$out"

$run "$bin" --help >/dev/null || fail "--help"
drivers=$($run "$bin" drivers) || fail "gswifi drivers does not run"
for d in ruijie eap-md5; do
	printf '%s\n' "$drivers" | grep -q "^$d " || fail "gswifi drivers does not list $d"
done
ok "gswifi drivers lists $(printf '%s\n' "$drivers" | sed 1d | wc -l | tr -d ' ') drivers"
[ -n "$($run "$bin" example-config)" ] || fail "gswifi example-config prints nothing"
ok "gswifi example-config"

# ---------------------------------------------------------------- size --

bytes=$(wc -c < "$bin" | tr -d ' ')
kib=$(( (bytes + 1023) / 1024 ))
echo "size: $bytes bytes ($kib KiB)"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "| target | size | linking |"
		echo "|---|---|---|"
		echo "| ${TARGET:-$(basename "$bin")} | $bytes bytes ($kib KiB) | $linking |"
	} >> "$GITHUB_STEP_SUMMARY"
fi

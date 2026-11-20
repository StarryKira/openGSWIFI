#!/bin/sh
#
# Imports the official OpenWrt root filesystem of a release as a Docker image,
# for the jobs that run things on "a router": the package install tests
# (ci/openwrt-test.sh) and the nftables check (ci/nft-check.sh).
#
#   openwrt-rootfs.sh <release> [target]     e.g. 24.10.8, 24.10.8 armsr/armv8
#
# The default target x86/64 becomes the image openwrt:<release>, any other
# one openwrt-<target>:<release> ("/" replaced by "-"). Prints the image name.
# Does nothing when the image is already there.

set -eu

release=${1:?usage: $0 <release> [target]}
target=${2:-x86/64}

flat=$(printf '%s' "$target" | tr / -)
if [ "$target" = x86/64 ]; then
	image=openwrt:$release
else
	image=openwrt-$flat:$release
fi

if docker image inspect "$image" >/dev/null 2>&1; then
	echo "openwrt-rootfs: $image is already imported" >&2
	echo "$image"
	exit 0
fi

base=https://downloads.openwrt.org/releases/$release/targets/$target
f=openwrt-$release-$flat-rootfs.tar.gz
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

curl -fsSL --retry 3 -o "$work/$f" "$base/$f"
sum=$(curl -fsSL --retry 3 "$base/sha256sums" | sed -n "s/ \*$f\$//p")
[ -n "$sum" ] || { echo "openwrt-rootfs: $f is not listed in $base/sha256sums" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
	echo "$sum  $work/$f" | sha256sum -c - >&2
else
	echo "$sum  $work/$f" | shasum -a 256 -c - >&2
fi

case "$target" in
x86/64) platform=linux/amd64 ;;
armsr/armv8) platform=linux/arm64 ;;
*) platform= ;;
esac
docker import ${platform:+--platform "$platform"} "$work/$f" "$image" >&2
echo "$image"

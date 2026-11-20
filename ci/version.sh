#!/bin/sh
#
# Works out the two versions the pipeline uses and prints them as key=value
# lines (the format of $GITHUB_OUTPUT):
#
#   cargo=0.1.0                       [workspace.package] version in Cargo.toml
#   version=0.1.0_git20261120070000   version of the packages
#
#   version.sh [tag]
#
# With a tag (given, or the one GitHub Actions is building), the tag must be
# v<cargo version> and the packages get exactly that version. Otherwise the
# packages are versioned <cargo version>_git<time of the last commit>, which
# every package manager orders after the release of the same number.
#
# OpenWrt Makefiles that carry a PKG_VERSION must agree with Cargo.toml.

set -eu

top=$(cd "$(dirname "$0")/.." && pwd)

tag=${1:-}
if [ -z "$tag" ] && [ "${GITHUB_REF_TYPE:-}" = tag ]; then
	tag=${GITHUB_REF_NAME:-}
fi

err() {
	# An annotation in GitHub Actions, a plain message elsewhere.
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		echo "::error::$*" >&2
	else
		echo "version.sh: $*" >&2
	fi
	exit 1
}

cargo=$(awk '
	/^\[/ { section = $0 }
	section == "[workspace.package]" && /^version[ \t]*=/ {
		gsub(/^[^"]*"|"[^"]*$/, "")
		print
		exit
	}' "$top/Cargo.toml")
[ -n "$cargo" ] || err "no [workspace.package] version in Cargo.toml"

for mk in "$top"/openwrt/*/Makefile; do
	[ -f "$mk" ] || continue
	mkv=$(sed -n 's/^PKG_VERSION:=//p' "$mk")
	[ -n "$mkv" ] || continue
	[ "$mkv" = "$cargo" ] || err "PKG_VERSION $mkv in ${mk#"$top"/} does not match Cargo.toml version $cargo"
done

if [ -n "$tag" ]; then
	[ "$tag" = "v$cargo" ] || err "tag $tag does not match Cargo.toml version $cargo (expected v$cargo)"
	version=$cargo
else
	# The time (UTC) of the commit being built; the current time in a tree
	# without commits.
	stamp=$(TZ=UTC git -C "$top" log -1 --format=%cd --date=format-local:%Y%m%d%H%M%S 2>/dev/null) || stamp=
	[ -n "$stamp" ] || stamp=$(date -u +%Y%m%d%H%M%S)
	version=$cargo-git$stamp
fi
# Package managers (apk in particular) want "_" where semver has "-":
# 1.0.0-rc1 -> 1.0.0_rc1, 1.0.0-git2026... -> 1.0.0_git2026...
version=$(printf '%s' "$version" | tr - _)

echo "cargo=$cargo"
echo "version=$version"

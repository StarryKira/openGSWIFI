#!/bin/sh
#
# Syntax-checks and shellchecks every shell script of the pipeline and of the
# OpenWrt packages: ci/*.sh, plus every file under openwrt/ that starts with a
# /bin/sh shebang (init scripts, rpcd plugins, uci-defaults, helpers).
#
#   lint-shell.sh
#
# Findings of severity "warning" and above fail the check; set
# SHELLCHECK_SEVERITY (error, warning, info, style) to move the bar.
#
# Uses the pinned shellcheck image when Docker is available, so that CI and
# developer machines agree, and shellcheck from PATH otherwise. Everything is
# checked as POSIX sh: the scripts run under busybox ash on the router and
# dash on the build machine.

set -eu

image=koalaman/shellcheck:v0.11.0
severity=${SHELLCHECK_SEVERITY:-warning}

top=$(cd "$(dirname "$0")/.." && pwd)
cd "$top"

list() {
	ls ci/*.sh
	[ -d openwrt ] || return 0
	find openwrt -type f | while IFS= read -r f; do
		case "$(head -n 1 "$f" 2>/dev/null | cut -c1-32)" in
		'#!/bin/sh'* | '#!/usr/bin/env sh'*) echo "$f" ;;
		esac
	done
}
files=$(list | sort -u)
echo "$files" | sed 's/^/  /'

rc=0
for f in $files; do
	sh -n "$f" || rc=1
done

# <extra shellcheck options> <file>...
check() {
	extra=$1
	shift
	[ $# -gt 0 ] || return 0
	# "local" is not POSIX, but every shell these run under has it and
	# OpenWrt's own scripts rely on it.
	# shellcheck disable=SC2086
	if [ "$how" = docker ]; then
		docker run --rm -e LANG=C.UTF-8 -v "$top:/mnt:ro" -w /mnt "$image" \
			-s sh -S "$severity" -e SC3043 $extra "$@" || rc=1
	else
		shellcheck -s sh -S "$severity" -e SC3043 $extra "$@" || rc=1
	fi
}

if docker version >/dev/null 2>&1; then
	how=docker
	echo "shellcheck: $image"
elif command -v shellcheck >/dev/null 2>&1; then
	how=path
	shellcheck --version | sed -n 2p
else
	echo "lint-shell: no docker to run $image in and no shellcheck in PATH" >&2
	exit 1
fi

# Init scripts are sourced by /etc/rc.common, which is what reads the
# variables they set (START, STOP, USE_PROCD...): SC2034 would flag each one.
init=
plain=
for f in $files; do
	case "$(head -n 1 "$f")" in
	*/etc/rc.common*) init="$init $f" ;;
	*) plain="$plain $f" ;;
	esac
done
# shellcheck disable=SC2086
check "" $plain
# shellcheck disable=SC2086
check "-e SC2034" $init

[ "$rc" = 0 ] && echo "lint-shell: $(echo "$files" | wc -l | tr -d ' ') scripts are clean"
exit "$rc"

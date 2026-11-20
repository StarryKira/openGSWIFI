#!/bin/sh
# SPDX-License-Identifier: MIT
#
# gswifi-proxy <gswifi proxy options...>
#
# Runs `gswifi proxy` and keeps the firewall honest about it: the redirect
# to the proxy is only installed while the proxy is accepting connections,
# so a connection is never sent to a port nobody listens on. The program
# calls back once its listener is up; when it is gone, for whatever reason,
# the rules are applied again without the redirect before this script
# exits and procd starts the next one.

PROG=/usr/bin/gswifi
RUN_DIR=/var/run/gswifi
READY=$RUN_DIR/proxy.ready
PROTECT=/usr/libexec/gswifi/protect

child=

on_term() {
	[ -n "$child" ] && kill -TERM "$child" 2>/dev/null
}

trap on_term TERM INT

mkdir -p "$RUN_DIR"
rm -f "$READY" "$RUN_DIR/proxy.stats"

"$PROG" proxy "$@" --stats "$RUN_DIR/proxy.stats" \
	--ready-cmd "echo \"\$GSWIFI_PROXY_PID\" > $READY && $PROTECT apply" &
child=$!

# `wait` also returns when a trapped signal arrives; keep waiting until
# the program has really exited.
rc=0
while kill -0 "$child" 2>/dev/null; do
	wait "$child"
	rc=$?
done

rm -f "$READY" "$RUN_DIR/proxy.stats"
"$PROTECT" apply >/dev/null 2>&1

exit "$rc"

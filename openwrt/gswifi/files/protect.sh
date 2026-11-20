#!/bin/sh
# SPDX-License-Identifier: MIT
#
# protect apply [force]   bring the protect rules in line with /etc/config/gswifi
# protect remove          take them out (service stop, package removal)
#
# One at a time: the init script, the proxy's callbacks and the LuCI app
# can all ask for this at the same moment.

case "$1" in
apply)
	set -- protect-apply ${2:+"$2"}
	;;
remove)
	set -- protect-remove
	;;
*)
	echo "usage: $0 apply [force] | remove" >&2
	exit 1
	;;
esac

mkdir -p /var/lock
exec flock /var/lock/gswifi-protect.lock /usr/libexec/gswifi/ctl "$@"

#!/bin/sh
# SPDX-License-Identifier: MIT
#
# gswifi-auth <device> <command...>
#
# Waits until the network device exists and has a link, then becomes the
# command (`gswifi run ...`). A session started on a device that is not
# there yet would exit at once and use up procd's respawn budget; one
# started without a link would spend its first round talking to nobody.
#
# procd tags what an instance prints with the name of this file, which is
# why it is called gswifi-auth: the sessions show up in the system log as
# "gswifi-auth[pid]".

dev=$1
shift

told=
while :; do
	if [ ! -e "/sys/class/net/$dev" ]; then
		why="网卡 $dev 不存在"
	elif [ "$(cat "/sys/class/net/$dev/carrier" 2>/dev/null)" != 1 ]; then
		why="网卡 $dev 没有链路"
	else
		break
	fi

	if [ "$told" != "$why" ]; then
		logger -t gswifi -p daemon.notice -- "$why，出现后自动开始认证"
		told=$why
	fi
	sleep 2
done

exec "$@"

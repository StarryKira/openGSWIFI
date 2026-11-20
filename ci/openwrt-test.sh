#!/bin/sh
#
# Installs and exercises the packages inside an OpenWrt x86-64 rootfs
# container.
#
#   openwrt-test.sh ipk|apk <package dir>
#
# The container runs no init: there is no procd, ubus, rpcd or netifd, so the
# service is not started. What is exercised instead is everything the
# service and the LuCI app are made of: the install scripts, UCI -> TOML
# generation (and that gswifi reads it back as intended), the status and rpcd
# backends, and removal. When the container may use netlink (docker run
# --cap-add NET_ADMIN, or --privileged), the traffic normalisation is
# installed for real too: its firewall include must pass `fw4 check`, the
# table must survive a firewall restart, and removal must take it out.

set -eu

fmt=${1:?usage: $0 ipk|apk <package dir>}
pkgs=${2:?package dir}

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
# <description> <expected> <actual>
expect() { [ "$2" = "$3" ] || fail "$1: expected [$2], got [$3]"; ok "$1"; }

RPC=/usr/libexec/rpcd/luci.gswifi
CTL=/usr/libexec/gswifi/ctl
ETC=/var/etc/gswifi
call() { printf '%s' "${2:-{\}}" | "$RPC" call "$1"; }
# <json> <jsonfilter expression>
j() { printf '%s\n' "$1" | jsonfilter -e "$2"; }
mode_of() { ls -ld "$1" | cut -c1-10; }

# /var points into /tmp, which starts out empty in a container.
mkdir -p /tmp/lock /tmp/run /tmp/log /tmp/state /tmp/.uci

# ------------------------------------------------------------ install --

if [ "$fmt" = ipk ]; then
	opkg update >/dev/null
	if opkg install "$pkgs"/gswifi_*_aarch64.ipk >/dev/null 2>&1; then
		fail "the aarch64 package installed on x86_64"
	fi
	opkg remove gswifi >/dev/null 2>&1 || true
	ok "the aarch64 package is refused on x86_64"
	opkg install "$pkgs"/gswifi_*_x86_64.ipk "$pkgs"/luci-app-gswifi_*_all.ipk
else
	apk update >/dev/null
	if apk add --allow-untrusted "$pkgs"/gswifi_*_aarch64.apk >/dev/null 2>&1; then
		fail "the aarch64 package installed on x86_64"
	fi
	apk del gswifi >/dev/null 2>&1 || true
	ok "the aarch64 package is refused on x86_64"
	apk add --allow-untrusted "$pkgs"/gswifi_*_x86_64.apk "$pkgs"/luci-app-gswifi_*_all.apk
fi

for f in /usr/bin/gswifi /etc/init.d/gswifi "$CTL" /usr/libexec/gswifi/gswifi-auth \
	/usr/libexec/gswifi/gswifi-proxy /usr/libexec/gswifi/protect "$RPC"; do
	[ -x "$f" ] || fail "$f missing or not executable"
done
for f in /etc/config/gswifi /usr/share/nftables.d/ruleset-post/90-gswifi.nft \
	/usr/share/ucode/gswifi/config.uc /usr/share/ucode/gswifi/toml.uc \
	/usr/share/ucode/gswifi/protect.uc /usr/share/ucode/gswifi/status.uc /usr/share/ucode/gswifi/util.uc \
	/www/luci-static/resources/gswifi/api.js \
	/www/luci-static/resources/view/gswifi/overview.js /www/luci-static/resources/view/gswifi/settings.js \
	/www/luci-static/resources/view/gswifi/protect.js /www/luci-static/resources/view/gswifi/log.js \
	/www/luci-static/resources/view/gswifi/tools.js \
	/usr/share/luci/menu.d/luci-app-gswifi.json /usr/share/rpcd/acl.d/luci-app-gswifi.json; do
	[ -f "$f" ] || fail "$f missing"
done
set -- /etc/rc.d/S*gswifi
[ -e "$1" ] || fail "service not enabled"
[ ! -e /etc/uci-defaults/90_gswifi ] || fail "uci-defaults script was not run"
expect "configuration is root only" "-rw-------" "$(mode_of /etc/config/gswifi)"
expect "protect is off by default" disabled "$(uci -q get gswifi.protect.mode)"
expect "the example network is off" 0 "$(uci -q get gswifi.campus.enabled)"
ok "files installed, service enabled"

/usr/bin/gswifi --version | grep -q '^gswifi ' || fail "gswifi --version"
ok "$(/usr/bin/gswifi --version)"

drivers=$(/usr/bin/gswifi drivers --json)
expect "first driver" ruijie "$(j "$drivers" '@[0].name')"
expect "ruijie needs no opt-in" false "$(j "$drivers" '@[@.name="ruijie"].experimental')"
expect "inode needs the experimental opt-in" true "$(j "$drivers" '@[@.name="inode"].experimental')"
expect "netkeeper cannot run a session" false "$(j "$drivers" '@[@.name="netkeeper"].runnable')"

jsonfilter -i /usr/share/luci/menu.d/luci-app-gswifi.json -e '@["admin/services/gswifi/protect"].action.path' >/dev/null ||
	fail "menu JSON"
jsonfilter -i /usr/share/rpcd/acl.d/luci-app-gswifi.json \
	-e '@["luci-app-gswifi"].write.ubus["luci.gswifi"][*]' | grep -qx control || fail "control missing from ACL"
ok "menu and ACL"

# --------------------------------------------- UCI -> TOML -> gswifi --
#
# Values with everything TOML (or a shell) would trip over. The user name
# comes back from `gswifi run --check` verbatim; the password is never
# printed, so its length in bytes is compared, and the same encoder writes
# both.

user='u"s\er #1 中文'"'"'q'
pass='p"a\ss#w $(id) `id` 密码'"'"'x
second line'

uci -q batch <<-'EOF'
	set gswifi.campus.enabled='1'
	set gswifi.campus.driver='ruijie'
	set gswifi.campus.device='lo'
	set gswifi.campus.client_version='4.10'
	set gswifi.campus.max_retries='bogus'
	add_list gswifi.campus.option='udp_heartbeat=true'
	add_list gswifi.campus.option='check_version="4.10"'
	add_list gswifi.campus.option='exit_on_reject=true'
	set gswifi.lab=network
	set gswifi.lab.enabled='1'
	set gswifi.lab.driver='inode'
	set gswifi.lab.device='lo'
	set gswifi.lab.username='h3c'
	set gswifi.lab.password='x'
	set gswifi.lab.experimental='0'
	set gswifi.off=network
	set gswifi.off.enabled='0'
	set gswifi.off.driver='eap-md5'
	set gswifi.off.username='u'
	set gswifi.off.password='p'
	commit gswifi
EOF
uci set "gswifi.campus.username=$user"
uci set "gswifi.campus.password=$pass"
uci commit gswifi

list=$("$CTL" networks 2>/tmp/networks.err)
expect "only complete, permitted networks are generated" "campus	lo	$ETC/net.campus.toml" "$list"
grep -q '实验性' /tmp/networks.err || fail "the refused experimental network was not reported"
grep -q 'exit_on_reject' /tmp/networks.err || fail "the reserved advanced option was not reported"
grep -q 'max_retries' /tmp/networks.err || fail "the invalid integer was not reported"
expect "generated TOML is root only" "-rw-------" "$(mode_of "$ETC/net.campus.toml")"
expect "its directory is root only" "drwx------" "$(mode_of "$ETC")"
grep -q 'id)' "$ETC/net.campus.toml" || fail "password missing from the TOML"

check=$(/usr/bin/gswifi run --check -c "$ETC/net.campus.toml") || { echo "$check"; fail "gswifi run --check"; }
expect "gswifi accepts the generated file" true "$(j "$check" '@.ok')"
expect "user name survives" "$user" "$(j "$check" '@.networks[0].username')"
expect "password length survives" "$(printf '%s' "$pass" | wc -c | tr -d ' ')" \
	"$(j "$check" '@.networks[0].password_bytes')"
case "$check" in *'id)'*|*'second line'*) fail "--check printed the password" ;; esac
expect "integers stay strings where the program wants one" "4.10" "$(j "$check" '@.networks[0].options.client_version')"
expect "advanced booleans are typed" true "$(j "$check" '@.networks[0].options.udp_heartbeat')"
expect "advanced quoted values are strings" "4.10" "$(j "$check" '@.networks[0].options.check_version')"
expect "invalid values fall back to the service default" -1 "$(j "$check" '@.networks[0].options.max_retries')"
expect "rejections never make the program exit" false "$(j "$check" '@.networks[0].exit_on_reject')"
expect "renewal goes through netifd" "ubus call network.interface.wan renew" \
	"$(j "$check" '@.networks[0].dhcp_script')"

# "0" is false, not a truthy string.
uci set gswifi.lab.experimental=1
uci commit gswifi
"$CTL" networks 2>/dev/null | grep -q '^lab	' || fail "experimental = 1 not honoured"
grep -qx 'experimental = true' "$ETC/net.lab.toml" || fail "experimental flag missing from the TOML"
uci set gswifi.lab.enabled=0
uci commit gswifi
"$CTL" networks >/dev/null 2>&1
[ ! -e "$ETC/net.lab.toml" ] || fail "the TOML of a disabled network (with its password) was left behind"
ok "experimental opt-in, strict booleans, cleanup of disabled networks"

# ----------------------------------------------------- status / rpcd --

"$RPC" list | jsonfilter -e '@.pppoe.username' >/dev/null || fail "rpcd list"
ok "rpcd list"

st=$(call status)
expect "status lists the networks in UCI order" "campus lab off" "$(j "$st" '@.networks[*].id' | tr '\n' ' ' | sed 's/ $//')"
expect "an enabled network without procd is not started" not-started "$(j "$st" '@.networks[0].state')"
expect "disabled network" disabled "$(j "$st" '@.networks[2].state')"
expect "the user name is in the status" "$user" "$(j "$st" '@.networks[0].username')"
case "$st" in *'id)'*) fail "the status JSON carries the password" ;; esac
expect "driver level is reported" field-tested "$(j "$st" '@.networks[0].support')"
ok "status JSON"

[ "$(call drivers | jsonfilter -e '@.drivers[*].name' | wc -l)" -ge 8 ] || fail "rpcd drivers"
expect "netkeeper calculator" 0 "$(call pppoe '{"version":4,"username":"u1"}' | jsonfilter -e '@.escaped' >/dev/null; echo $?)"
call pppoe '{"version":15,"username":"u1"}' | jsonfilter -e '@.error' | grep -q 'nk_version 15' ||
	fail "unsupported NetKeeper profiles must say so"
expect "control refuses odd network names" 1 "$(call control '{"action":"restart","id":"../x"}' | jsonfilter -e '@.code')"
expect "control refuses unknown actions" 1 "$(call control '{"action":"rm"}' | jsonfilter -e '@.code')"
call diag | jsonfilter -e '@.output' > /tmp/diag.txt
grep -q "password='\*\*\*\*\*\*\*\*'" /tmp/diag.txt || fail "diag does not mask the password"
if grep -q 'id)\|second line' /tmp/diag.txt; then fail "diag carries the password"; fi
ok "rpcd calls"

# -------------------------------------------------- traffic normalisation --

uci -q batch <<-'EOF'
	set gswifi.protect.mode='observe'
	delete gswifi.protect.wan
	add_list gswifi.protect.wan_device='lo'
	delete gswifi.protect.lan
	add_list gswifi.protect.lan_device='dummy-lan'
	add_list gswifi.protect.dns_blocked_domain='telemetry.example'
	commit gswifi
EOF
show=$("$CTL" protect-show)
echo "$show" | grep -q '^table inet gswifi {' || { echo "$show"; fail "protect-show"; }
echo "$show" | grep -q 'oifname "lo"' || fail "upstream device missing from the rules"
echo "$show" | grep -q 'counter name "ttl4"$\|counter name "ttl4" comment' || fail "observe rules must only count"
ok "protect rules are generated from UCI"

if nft list tables >/dev/null 2>&1; then
	before_ttl=$(cat /proc/sys/net/ipv4/ip_default_ttl)
	sysctl_rw=0
	# /proc/sys is read-only unless the container is privileged.
	if (echo "$before_ttl" > /proc/sys/net/ipv4/ip_default_ttl) 2>/dev/null; then sysctl_rw=1; fi

	/usr/libexec/gswifi/protect apply || fail "protect apply (observe)"
	nft list table inet gswifi >/dev/null || fail "inet gswifi table not loaded"
	nft list counters table inet gswifi | grep -q 'counter ttl4' || fail "ttl4 counter missing"
	expect "observe changes no kernel parameter" "$before_ttl" "$(cat /proc/sys/net/ipv4/ip_default_ttl)"
	expect "status reports the counters" ttl4 "$(call protect | jsonfilter -e '@.counters[0].name')"
	ok "observe mode installed"

	# The include sits at the top level of fw4's ruleset (ruleset-post), not
	# inside table inet fw4 like /etc/nftables.d: unindented, after the table.
	fw4 -q print 2>/dev/null | grep -qx 'include "/usr/share/nftables.d/ruleset-post/90-gswifi.nft"' ||
		fail "fw4 does not include the rules at the top level"
	fw4 -q check || fail "fw4 check with the include"
	fw4 restart >/dev/null 2>&1 || true
	nft list table inet fw4 >/dev/null || fail "the firewall did not come back after a restart"
	nft list table inet gswifi >/dev/null || fail "the table did not survive a firewall restart"
	ok "firewall restart keeps fw4 and inet gswifi"

	uci set gswifi.protect.mode=enforce
	uci commit gswifi
	/usr/libexec/gswifi/protect apply || fail "protect apply (enforce)"
	nft list table inet gswifi | grep -q 'ip ttl set 128' || fail "enforce rules"
	if [ "$sysctl_rw" = 1 ]; then
		expect "enforce sets the persona TTL" 128 "$(cat /proc/sys/net/ipv4/ip_default_ttl)"
	fi
	ok "enforce mode installed"

	uci set gswifi.protect.mode=disabled
	uci commit gswifi
	/usr/libexec/gswifi/protect apply || fail "protect apply (disabled)"
	nft list table inet gswifi >/dev/null 2>&1 && fail "table left behind when disabled"
	expect "kernel parameters restored" "$before_ttl" "$(cat /proc/sys/net/ipv4/ip_default_ttl)"
	fw4 -q check || fail "fw4 check without the rules file"
	ok "disabling removes the table and restores the kernel parameters"

	# Removal has to clean up whatever the mode was.
	uci set gswifi.protect.mode=observe
	uci commit gswifi
	/usr/libexec/gswifi/protect apply || fail "protect apply before removal"
	nft list table inet gswifi >/dev/null || fail "table not loaded before removal"
	have_nft=1
else
	echo "skip: no netlink in this container (run it with --cap-add NET_ADMIN to install the rules for real)"
	have_nft=0
fi

# ------------------------------------------------------------- remove --

if [ "$fmt" = ipk ]; then
	opkg remove luci-app-gswifi gswifi
else
	apk del luci-app-gswifi gswifi
fi
for f in /usr/bin/gswifi /etc/init.d/gswifi "$CTL" "$RPC" /usr/share/nftables.d/ruleset-post/90-gswifi.nft; do
	[ ! -e "$f" ] || fail "$f left behind after removal"
done
[ ! -e "$ETC" ] || fail "$ETC (generated configuration with the password) left behind"
[ ! -e /var/run/gswifi ] || fail "/var/run/gswifi left behind"
set -- /etc/rc.d/*gswifi
[ ! -e "$1" ] || fail "service links left behind"
if [ "$have_nft" = 1 ]; then
	nft list table inet gswifi >/dev/null 2>&1 && fail "inet gswifi table left behind after removal"
	fw4 -q check || fail "fw4 check after removal"
	ok "removal took the rules out"
fi
ok "removed"

echo "all OpenWrt $fmt tests passed"

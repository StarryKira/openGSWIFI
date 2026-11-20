#!/bin/sh
#
# Install and exercise the .deb or .rpm packages inside a container of a
# distribution that uses them (no systemd running there, so the service itself
# is not started; the unit is checked with systemd-analyze instead).
#
#   linux-test.sh deb|rpm <package dir>

set -eu

fmt=${1:?usage: $0 deb|rpm <package dir>}
pkgs=${2:?package dir}

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
# <description> <expected> <actual>
expect() { [ "$2" = "$3" ] || fail "$1: expected [$2], got [$3]"; ok "$1"; }

CONF=/etc/gswifi/config.toml
UNIT=/usr/lib/systemd/system/gswifi.service

if [ "$fmt" = deb ]; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends systemd >/dev/null
	arch=$(dpkg --print-architecture)
	case $arch in amd64) other=arm64 ;; *) other=amd64 ;; esac
	native=$(ls "$pkgs"/gswifi_*_"$arch".deb)
	foreign=$(ls "$pkgs"/gswifi_*_"$other".deb)
	pkg_install() { dpkg -i "$1"; }
	pkg_reinstall() { dpkg -i "$1"; }
	pkg_remove() { dpkg --purge gswifi; }
	installed() { dpkg -s gswifi >/dev/null 2>&1; }
else
	if command -v dnf >/dev/null; then dnf install -q -y systemd >/dev/null; else yum install -q -y systemd >/dev/null; fi
	arch=$(uname -m)
	case $arch in x86_64) other=aarch64 ;; *) other=x86_64 ;; esac
	native=$(ls "$pkgs"/gswifi-*."$arch".rpm)
	foreign=$(ls "$pkgs"/gswifi-*."$other".rpm)
	# The packages are not signed, which rpm 6 refuses by default. (dnf
	# installs a local package anyway, with a warning.)
	pkg_install() { rpm -i --nosignature "$1"; }
	pkg_reinstall() { rpm -U --replacepkgs --nosignature "$1"; }
	pkg_remove() { rpm -e gswifi; }
	installed() { rpm -q gswifi >/dev/null 2>&1; }
fi
echo "testing $native on $(. /etc/os-release; echo "$PRETTY_NAME") ($arch)"

# ------------------------------------------------------------ install --

if pkg_install "$foreign" >/dev/null 2>&1; then
	fail "the $other package installed on $arch"
fi
installed && fail "the $other package left gswifi installed"
ok "the $other package is refused on $arch"

pkg_install "$native"
installed || fail "gswifi is not installed"

[ -x /usr/bin/gswifi ] || fail "/usr/bin/gswifi missing or not executable"
for f in "$UNIT" "$CONF" /usr/share/doc/gswifi/copyright; do
	[ -f "$f" ] || fail "$f missing"
done
expect "config is private" "600 root root" "$(stat -c '%a %U %G' "$CONF")"
ok "files installed"

/usr/bin/gswifi --version | grep -q '^gswifi ' || fail "gswifi --version"
ok "$(/usr/bin/gswifi --version)"
/usr/bin/gswifi drivers | grep -q '^ruijie ' || fail "gswifi drivers"
ok "gswifi drivers"

# --------------------------------------------------- shipped config --

# As shipped, the configuration is valid but names no network: the service
# says so and authenticates nothing.
rc=0
out=$(/usr/bin/gswifi run --config "$CONF" 2>&1) || rc=$?
expect "unconfigured service exits with an error" 1 "$rc"
printf '%s\n' "$out" | grep -q 'networks' || fail "unconfigured service does not ask for [[networks]]: $out"
ok "unconfigured service asks for a [[networks]] section"

# With the template uncommented and filled in, gswifi gets past the
# configuration and as far as looking for the interface (one that does not
# exist, so that nothing is sent anywhere).
nic=gswifi-ci0
sed -e 's/^#\([a-z[]\)/\1/' \
	-e "s/^interface = .*/interface = \"$nic\"/" \
	-e 's/^username = ""/username = "someone"/' \
	-e 's/^password = ""/password = "secret"/' "$CONF" > /tmp/gswifi-ci.toml
grep -q '^\[\[networks\]\]$' /tmp/gswifi-ci.toml || fail "no [[networks]] template in $CONF"
rc=0
out=$(/usr/bin/gswifi run --config /tmp/gswifi-ci.toml 2>&1) || rc=$?
expect "a missing interface is an error the unit retries" 1 "$rc"
printf '%s\n' "$out" | grep -q "$nic" || fail "the filled-in template is not accepted: $out"
ok "the filled-in template is a valid configuration"
rm -f /tmp/gswifi-ci.toml

# The same file as the [protect] source: no section means disabled.
/usr/bin/gswifi protect show --config "$CONF" >/dev/null 2>&1 || fail "gswifi protect show rejects the shipped config"
ok "gswifi protect show accepts the shipped config"

# ------------------------------------------------------------- unit --

grep -q '^ExecStart=/usr/bin/gswifi run --config /etc/gswifi/config.toml$' "$UNIT" || fail "unexpected ExecStart in $UNIT"
grep -q '^Restart=on-failure$' "$UNIT" || fail "the unit does not restart on failure"
# Rejected credentials (exit_on_reject = true) must not be retried.
grep -q '^RestartPreventExitStatus=2 3$' "$UNIT" || fail "the unit retries rejected credentials"
out=$(systemd-analyze verify "$UNIT" 2>&1) || fail "systemd-analyze verify: $out"
if printf '%s\n' "$out" | grep gswifi; then
	fail "systemd-analyze verify complains about the unit"
fi
ok "systemd-analyze verify"

# ---------------------------------------------------- reinstall, remove --

sed -i 's/^#username = ""/username = "someone"/' "$CONF"
pkg_reinstall "$native" >/dev/null
grep -q '^username = "someone"' "$CONF" || fail "reinstalling replaced the edited config"
expect "edited config is still private" "600" "$(stat -c '%a' "$CONF")"
ok "reinstall keeps the edited config"

pkg_remove
installed && fail "gswifi is still installed"
[ ! -e /usr/bin/gswifi ] || fail "/usr/bin/gswifi left behind"
[ ! -e "$UNIT" ] || fail "$UNIT left behind"
ok "removed"

echo "all tests passed"

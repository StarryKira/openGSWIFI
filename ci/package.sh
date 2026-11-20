#!/bin/sh
#
# Builds the OpenWrt packages from the static binaries of the build job.
#
#   package.sh ipk <version> <bindir> <outdir>   opkg, OpenWrt <= 24.10 (needs GNU tar)
#   package.sh apk <version> <bindir> <outdir>   apk, OpenWrt >= 25.12 (needs `apk mkpkg`,
#                                                 i.e. apk-tools 3: run it in Alpine)
#
# <bindir> holds gswifi-<family> for every family in FAMILIES (the exec bit
# may be missing: GitHub's artifact download drops it). <version> must
# already be valid for apk (1.2.3, 1.2.3_rc1, 1.2.3_git20261120...), see
# ci/version.sh. Writes gswifi_<version>_<family>.<fmt> for each family and
# luci-app-gswifi_<version>_all.<fmt>.
#
# The core package of each family holds one static binary that runs on every
# OpenWrt architecture of that CPU family, so it is built as an
# architecture-independent package whose pre-install script refuses routers
# of another family. The LuCI app is architecture-independent anyway.
#
# The files and where they go are the same as in openwrt/gswifi/Makefile
# (the SDK build); keep the two in step.

set -eu

fmt=${1:?usage: $0 ipk|apk <version> <bindir> <outdir>}
version=${2:?version}
bindir=${3:?bindir}
outdir=${4:?outdir}
release=${PKG_RELEASE:-1}

top=$(cd "$(dirname "$0")/.." && pwd)
files=$top/openwrt/gswifi/files
luci=$top/openwrt/luci-app-gswifi

FAMILIES="x86_64 aarch64 armv7"
URL=https://github.com/StarryKira/openGSWIFI
MAINTAINER=fuqiuluo
# Reproducible archives: every file gets the time of the commit being built.
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$top" log -1 --format=%ct 2>/dev/null || date +%s)}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$outdir"

for fam in $FAMILIES; do
	[ -f "$bindir/gswifi-$fam" ] || { echo "package.sh: $bindir/gswifi-$fam is missing" >&2; exit 1; }
done

# DISTRIB_ARCH patterns (case syntax) of the routers a family's binary runs on.
#   armv7: built soft-float (armv7-unknown-linux-musleabi), runs on any ARMv7
family_archs() {
	case "$1" in
	x86_64) echo 'x86_64' ;;
	aarch64) echo 'aarch64_*' ;;
	armv7) echo 'arm_cortex-a*' ;;
	*) echo "unknown family $1" >&2; exit 1 ;;
	esac
}

# ---------------------------------------------------------------- scripts --

# <file> <family>
write_guard() {
	cat > "$1" <<EOF
#!/bin/sh
# This package carries the gswifi binary for $2 routers only.
[ -n "\${IPKG_INSTROOT}" ] && exit 0
arch=\$(. /etc/openwrt_release 2>/dev/null; echo "\$DISTRIB_ARCH")
case "\$arch" in
''|$(family_archs "$2")) exit 0 ;;
esac
echo "gswifi: this package is for $2 routers, but this router is \$arch." >&2
echo "gswifi: download the package matching your router from the release page." >&2
exit 1
EOF
}

write_core_postinst() {
	cat > "$1" <<'EOF'
#!/bin/sh
if [ -n "${IPKG_INSTROOT}" ]; then
	/bin/sh "${IPKG_INSTROOT}/etc/rc.common" "${IPKG_INSTROOT}/etc/init.d/gswifi" enable
	exit 0
fi
# What the first boot of an image would do with the uci-defaults script.
f=/etc/uci-defaults/90_gswifi
if [ -f "$f" ]; then
	( . "$f" ) && rm -f "$f"
fi
/etc/init.d/gswifi enable
# Restart so that an upgrade takes effect. Only networks that are enabled
# and complete in /etc/config/gswifi are started; the protect rules follow
# the configuration (mode "disabled" by default).
/etc/init.d/gswifi restart >/dev/null 2>&1
rm -f /tmp/luci-indexcache /tmp/luci-indexcache.*
exit 0
EOF
}

# Stopping takes the protect rules out: the inet gswifi table, the dnsmasq
# fragment, the kernel parameters it changed. The firewall include file goes
# with the package's files.
write_core_prerm() {
	cat > "$1" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/gswifi stop >/dev/null 2>&1
/etc/init.d/gswifi disable >/dev/null 2>&1
/usr/libexec/gswifi/protect remove >/dev/null 2>&1
exit 0
EOF
}

write_core_postrm() {
	cat > "$1" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -rf /var/run/gswifi /var/etc/gswifi
rm -f /var/lock/gswifi-protect.lock
exit 0
EOF
}

# Installed and removed alike: drop LuCI's caches and let rpcd (SIGHUP makes
# it re-execute itself) pick up or forget the luci.gswifi ubus object.
write_luci_refresh() {
	cat > "$1" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache /tmp/luci-indexcache.*
rm -rf /tmp/luci-modulecache/
killall -HUP rpcd 2>/dev/null
exit 0
EOF
}

# ---------------------------------------------------------------- staging --

# <family> <root>
stage_core() {
	r=$2
	mkdir -p "$r/usr/bin" "$r/etc/config" "$r/etc/init.d" "$r/etc/uci-defaults" \
		"$r/usr/libexec/gswifi" "$r/usr/share/ucode/gswifi" "$r/usr/share/nftables.d/ruleset-post"
	cp "$bindir/gswifi-$1" "$r/usr/bin/gswifi"
	cp "$files/gswifi.config" "$r/etc/config/gswifi"
	cp "$files/gswifi.init" "$r/etc/init.d/gswifi"
	cp "$files/gswifi.defaults" "$r/etc/uci-defaults/90_gswifi"
	cp "$files/ctl.uc" "$r/usr/libexec/gswifi/ctl"
	cp "$files/auth.sh" "$r/usr/libexec/gswifi/gswifi-auth"
	cp "$files/proxy.sh" "$r/usr/libexec/gswifi/gswifi-proxy"
	cp "$files/protect.sh" "$r/usr/libexec/gswifi/protect"
	cp "$files"/lib/*.uc "$r/usr/share/ucode/gswifi/"
	cp "$files/gswifi.nft" "$r/usr/share/nftables.d/ruleset-post/90-gswifi.nft"
	fix_modes "$r"
	chmod 0755 "$r/usr/bin/gswifi" "$r/etc/init.d/gswifi" "$r/etc/uci-defaults/90_gswifi" \
		"$r/usr/libexec/gswifi/ctl" "$r/usr/libexec/gswifi/gswifi-auth" \
		"$r/usr/libexec/gswifi/gswifi-proxy" "$r/usr/libexec/gswifi/protect"
	# It holds the account password.
	chmod 0600 "$r/etc/config/gswifi"
}

# <root>
stage_luci() {
	r=$1
	mkdir -p "$r/www"
	cp -R "$luci/htdocs/." "$r/www/"
	cp -R "$luci/root/." "$r/"
	fix_modes "$r"
	chmod 0755 "$r/usr/libexec/rpcd/luci.gswifi"
}

# Directories 0755 (the staging root included: it becomes "/" on the
# router), files 0644 until made executable explicitly.
fix_modes() {
	find "$1" -type d -exec chmod 0755 {} \;
	find "$1" -type f -exec chmod 0644 {} \;
}

# ------------------------------------------------------------------- ipk --

tar_dir() {
	tar --format=gnu --numeric-owner --owner=0 --group=0 --sort=name \
		--mtime="@$epoch" -C "$1" -cf - .
}

# <name> <family or "all"> <depends> <description> <root> <scriptdir> <conffiles>
make_ipk() {
	d=$work/ipk-$1-$2
	mkdir -p "$d/control"

	size=$(du -sb "$5" | cut -f1)
	{
		echo "Package: $1"
		echo "Version: $version-r$release"
		echo "Depends: $3"
		echo "Source: $URL"
		echo "SourceName: $1"
		echo "License: MIT"
		echo "Section: net"
		echo "URL: $URL"
		echo "Maintainer: $MAINTAINER"
		echo "Architecture: all"
		echo "Installed-Size: $size"
		echo "Description:  $4"
	} > "$d/control/control"
	[ -z "$7" ] || echo "$7" > "$d/control/conffiles"

	for s in preinst postinst prerm postrm; do
		[ -f "$6/$s" ] && cp "$6/$s" "$d/control/$s"
	done
	fix_modes "$d/control"
	for s in preinst postinst prerm postrm; do
		[ -f "$d/control/$s" ] && chmod 0755 "$d/control/$s"
	done

	echo "2.0" > "$d/debian-binary"
	tar_dir "$5" | gzip -9n > "$d/data.tar.gz"
	tar_dir "$d/control" | gzip -9n > "$d/control.tar.gz"

	out=$outdir/${1}_${version}_$2.ipk
	tar --format=gnu --numeric-owner --owner=0 --group=0 --mtime="@$epoch" \
		-C "$d" -cf - ./debian-binary ./data.tar.gz ./control.tar.gz | gzip -9n > "$out"
	echo "$out"
}

# ------------------------------------------------------------------- apk --

# <name> <family or "all"> <depends> <description> <root> <scriptdir> <conffiles>
make_apk() {
	if [ -n "$7" ]; then
		# OpenWrt's sysupgrade and package tools look for conffiles here.
		mkdir -p "$5/lib/apk/packages"
		echo "$7" > "$5/lib/apk/packages/$1.conffiles"
		chmod 0755 "$5/lib" "$5/lib/apk" "$5/lib/apk/packages"
		chmod 0644 "$5/lib/apk/packages/$1.conffiles"
	fi

	scripts=
	[ -f "$6/preinst" ] && scripts="$scripts --script pre-install:$6/preinst --script pre-upgrade:$6/preinst"
	[ -f "$6/postinst" ] && scripts="$scripts --script post-install:$6/postinst --script post-upgrade:$6/postinst"
	[ -f "$6/prerm" ] && scripts="$scripts --script pre-deinstall:$6/prerm"
	[ -f "$6/postrm" ] && scripts="$scripts --script post-deinstall:$6/postrm"

	out=$outdir/${1}_${version}_$2.apk
	# shellcheck disable=SC2086 # $scripts is a list of options
	apk mkpkg \
		--info "name:$1" \
		--info "version:$version-r$release" \
		--info "arch:noarch" \
		--info "description:$4" \
		--info "license:MIT" \
		--info "origin:$1" \
		--info "url:$URL" \
		--info "maintainer:$MAINTAINER" \
		--info "depends:$3" \
		$scripts \
		--files "$5" \
		--output "$out"
	echo "$out"
}

# ------------------------------------------------------------------ main --

core_deps="ucode ucode-mod-fs ucode-mod-uci ucode-mod-ubus jsonfilter"
luci_deps="luci-base rpcd ucode gswifi"

case "$fmt" in
ipk)
	make_pkg=make_ipk
	# opkg wants a comma separated list.
	core_depends=$(echo "$core_deps" | sed 's/ /, /g')
	luci_depends=$(echo "$luci_deps" | sed 's/ /, /g')
	;;
apk)
	make_pkg=make_apk
	core_depends=$core_deps
	luci_depends=$luci_deps
	;;
*) echo "unknown format: $fmt" >&2; exit 1 ;;
esac

for fam in $FAMILIES; do
	root=$work/root-$fam
	sd=$work/scripts-$fam
	mkdir -p "$root" "$sd"
	stage_core "$fam" "$root"
	write_guard "$sd/preinst" "$fam"
	write_core_postinst "$sd/postinst"
	write_core_prerm "$sd/prerm"
	write_core_postrm "$sd/postrm"
	chmod 0755 "$sd"/*
	$make_pkg gswifi "$fam" "$core_depends" \
		"Open GSWIFI campus network authentication client, procd service and traffic normalisation ($fam build)" \
		"$root" "$sd" /etc/config/gswifi
done

root=$work/root-luci
sd=$work/scripts-luci
mkdir -p "$root" "$sd"
stage_luci "$root"
write_luci_refresh "$sd/postinst"
write_luci_refresh "$sd/postrm"
chmod 0755 "$sd"/*
$make_pkg luci-app-gswifi all "$luci_depends" \
	"LuCI pages for Open GSWIFI: status, settings, anti sharing detection, log and tools" \
	"$root" "$sd" ""

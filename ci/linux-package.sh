#!/bin/sh
#
# Builds the .deb and .rpm packages for desktop/server Linux from the static
# binaries of the build job.
#
#   linux-package.sh deb <version> <bindir> <outdir>   needs dpkg-deb
#   linux-package.sh rpm <version> <bindir> <outdir>   needs rpmbuild
#
# <bindir> contains gswifi-<family> for every family in FAMILIES. <version>
# is the apk-style version of the other packages (1.2.3, 1.2.3_rc1,
# 1.2.3_git20261114...). The binaries are static, so one package per CPU
# family runs on any distribution and depends on nothing.
#
# Needs GNU coreutils (touch -d @epoch, du --exclude): run it on Linux.

set -eu

fmt=${1:?usage: $0 deb|rpm <version> <bindir> <outdir>}
version=${2:?version}
bindir=${3:?bindir}
outdir=${4:?outdir}
release=${PKG_RELEASE:-1}

top=$(cd "$(dirname "$0")/.." && pwd)
files=$top/linux

FAMILIES="x86_64 aarch64 armv7"
URL=https://github.com/StarryKira/openGSWIFI
MAINTAINER="Open GSWIFI contributors"
SUMMARY="Multi-protocol campus network authentication client"
DESCRIPTION="Authenticates network interfaces against campus networks: Ruijie, Saier
and plain 802.1X (EAP-MD5), H3C iNode and Portal, Dr.com, Anlang and web
portals. Runs as the systemd service gswifi, configured in
/etc/gswifi/config.toml."
# Reproducible packages: every file gets the time of the commit being built.
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$top" log -1 --format=%ct 2>/dev/null || date +%s)}
export SOURCE_DATE_EPOCH="$epoch"

# deb and rpm both order "~" before and "+" after the plain version, like
# apk does with _rc and _git: 1.2.3_rc1 -> 1.2.3~rc1, 1.2.3_git... -> 1.2.3+git...
# File names keep <version>, as GitHub rewrites "~" and "+" in release assets.
pkgver=$(printf '%s' "$version" | sed -e 's/_git/+git/' -e 's/_/~/g')

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
bindir=$(cd "$bindir" && pwd)

# <family> <deb|rpm>
pkg_arch() {
	case "$1:$2" in
	x86_64:deb) echo amd64 ;;
	aarch64:deb) echo arm64 ;;
	# The binary is soft-float, but static: it runs on hard-float systems too.
	armv7:deb) echo armhf ;;
	x86_64:rpm) echo x86_64 ;;
	aarch64:rpm) echo aarch64 ;;
	armv7:rpm) echo armv7hl ;;
	*) echo "unknown family $1" >&2; exit 1 ;;
	esac
}

# <family> <root>
stage() {
	r=$2
	[ -f "$bindir/gswifi-$1" ] || { echo "linux-package: $bindir/gswifi-$1 is missing" >&2; exit 1; }
	mkdir -p "$r/usr/bin" "$r/usr/lib/systemd/system" "$r/etc/gswifi" \
		"$r/usr/share/doc/gswifi"
	cp "$bindir/gswifi-$1" "$r/usr/bin/gswifi"
	cp "$files/gswifi.service" "$r/usr/lib/systemd/system/gswifi.service"
	cp "$files/config.toml" "$r/etc/gswifi/config.toml"
	cp "$top/README.md" "$r/usr/share/doc/gswifi/README.md"
	cp "$top/LICENSE" "$r/usr/share/doc/gswifi/copyright"
	find "$r" -type d -exec chmod 0755 {} \;
	find "$r" -type f -exec chmod 0644 {} \;
	chmod 0755 "$r/usr/bin/gswifi"
	# It holds the password.
	chmod 0600 "$r/etc/gswifi/config.toml"
	find "$r" -exec touch -h -d "@$epoch" {} +
}

HINT='echo "gswifi: fill in /etc/gswifi/config.toml, then run: systemctl enable --now gswifi"'

# ------------------------------------------------------------------- deb --

make_deb() {
	fam=$1
	arch=$(pkg_arch "$fam" deb)
	r=$work/deb-$fam
	stage "$fam" "$r"
	mkdir -p "$r/DEBIAN"

	{
		echo "Package: gswifi"
		echo "Version: $pkgver-$release"
		echo "Architecture: $arch"
		echo "Maintainer: $MAINTAINER"
		echo "Installed-Size: $(du -sk --exclude=DEBIAN "$r" | cut -f1)"
		echo "Section: net"
		echo "Priority: optional"
		echo "Homepage: $URL"
		echo "Description: $SUMMARY"
		printf '%s\n' "$DESCRIPTION" | sed 's/^/ /'
	} > "$r/DEBIAN/control"
	echo /etc/gswifi/config.toml > "$r/DEBIAN/conffiles"

	cat > "$r/DEBIAN/postinst" <<EOF
#!/bin/sh
set -e
[ "\$1" = configure ] || exit 0
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	# An upgrade restarts a running service with the new binary.
	[ -z "\$2" ] || systemctl try-restart gswifi.service >/dev/null 2>&1 || true
fi
[ -n "\$2" ] || $HINT
exit 0
EOF
	cat > "$r/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
	systemctl disable --now gswifi.service >/dev/null 2>&1 || true
fi
exit 0
EOF
	cat > "$r/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
	chmod 0755 "$r/DEBIAN" "$r/DEBIAN/postinst" "$r/DEBIAN/prerm" "$r/DEBIAN/postrm"
	chmod 0644 "$r/DEBIAN/control" "$r/DEBIAN/conffiles"
	find "$r/DEBIAN" -exec touch -h -d "@$epoch" {} +

	out=$outdir/gswifi_${version}-${release}_$arch.deb
	# xz rather than dpkg's newer zstd default, so older dpkg can read it.
	dpkg-deb --root-owner-group -Zxz --build "$r" "$out" >/dev/null
	echo "$out"
}

# ------------------------------------------------------------------- rpm --

make_rpm() {
	fam=$1
	arch=$(pkg_arch "$fam" rpm)
	r=$work/rpm-$fam
	stage "$fam" "$r"
	top_rpm=$work/rpmbuild-$fam
	mkdir -p "$top_rpm"

	cat > "$work/gswifi-$fam.spec" <<EOF
Name: gswifi
Version: $pkgver
Release: $release
Summary: $SUMMARY
License: MIT
URL: $URL
Packager: $MAINTAINER
# A prebuilt static binary: nothing to strip, no debuginfo, no dependencies.
AutoReqProv: no
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

%description
$DESCRIPTION

%install
cp -a "$r/." "%{buildroot}/"

%post
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || :
fi
[ "\$1" -gt 1 ] || $HINT

%preun
if [ "\$1" -eq 0 ] && [ -d /run/systemd/system ]; then
	systemctl disable --now gswifi.service >/dev/null 2>&1 || :
fi

%postun
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || :
	# An upgrade restarts a running service with the new binary.
	[ "\$1" -lt 1 ] || systemctl try-restart gswifi.service >/dev/null 2>&1 || :
fi

%files
%attr(0755,root,root) /usr/bin/gswifi
%attr(0644,root,root) /usr/lib/systemd/system/gswifi.service
%dir %attr(0755,root,root) /etc/gswifi
%config(noreplace) %attr(0600,root,root) /etc/gswifi/config.toml
%dir %attr(0755,root,root) /usr/share/doc/gswifi
%doc %attr(0644,root,root) /usr/share/doc/gswifi/README.md
%license %attr(0644,root,root) /usr/share/doc/gswifi/copyright
EOF

	# gzip payload and SHA-256 digests, which every rpm still in use reads.
	# The mtime clamp is spelled both ways: rpm < 4.20 only knows the first,
	# newer ones warn about it and want the second.
	rpmbuild -bb --quiet --target "$arch-linux" \
		--define "_topdir $top_rpm" \
		--define "_binary_payload w9.gzdio" \
		--define "_buildhost reproducible" \
		--define "use_source_date_epoch_as_buildtime 1" \
		--define "clamp_mtime_to_source_date_epoch 1" \
		--define "build_mtime_policy clamp_to_source_date_epoch" \
		"$work/gswifi-$fam.spec" >/dev/null

	out=$outdir/gswifi-${version}-${release}.$arch.rpm
	cp "$top_rpm/RPMS/$arch/gswifi-${pkgver}-${release}.$arch.rpm" "$out"
	echo "$out"
}

# ------------------------------------------------------------------ main --

case "$fmt" in
deb) make_pkg=make_deb ;;
rpm) make_pkg=make_rpm ;;
*) echo "unknown format: $fmt" >&2; exit 1 ;;
esac

for fam in $FAMILIES; do
	$make_pkg "$fam"
done

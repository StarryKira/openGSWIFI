#!/bin/sh
#
# cross-rs pre-build hook (see Cross.toml). Runs as root while the cross image
# for a target is being built and installs a static libpcap for that target
# into /opt/libpcap; Cross.toml then points LIBPCAP_LIBDIR at /opt/libpcap/lib.
#
#   build-libpcap.sh <target triple>
#
# Keep "version" in step with LIBPCAP_VER in Cross.toml (the lint job checks).

set -eu

target=${1:?usage: $0 <target triple>}
version=1.10.7
sha256=68fa62cffb974f4275641ce14c2e2d75739251f30e00e6a0900903b247d76a03

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
	bison flex make curl ca-certificates xz-utils >/dev/null

# The cross images name their C compiler in CC_<target> (and, in newer
# images, the tool prefix in CROSS_TOOLCHAIN_PREFIX).
if [ -n "${CROSS_TOOLCHAIN_PREFIX:-}" ]; then
	cc=${CROSS_TOOLCHAIN_PREFIX}gcc
else
	var=CC_$(printf '%s' "$target" | tr '-' '_')
	eval "cc=\${$var:-}"
fi
if [ -z "$cc" ]; then
	echo "build-libpcap: cannot find the C compiler for $target in this image" >&2
	exit 1
fi
host=$(basename "${cc%-gcc}")
echo "build-libpcap: libpcap $version for $target, compiler $cc, host $host"

work=$(mktemp -d)
cd "$work"
curl -fsSL --retry 3 -o libpcap.tar.xz "https://www.tcpdump.org/release/libpcap-$version.tar.xz"
echo "$sha256  libpcap.tar.xz" | sha256sum -c -
tar -xJf libpcap.tar.xz
cd "libpcap-$version"

# One section per function, so that the linker (rustc passes --gc-sections)
# keeps only what gswifi calls. Capture from a Linux interface is all that is
# needed: everything optional is switched off.
./configure --host="$host" --prefix=/opt/libpcap CC="$cc" \
	CFLAGS="-Os -fPIC -ffunction-sections -fdata-sections" \
	--disable-shared --with-pcap=linux --without-libnl \
	--disable-usb --disable-netmap --disable-bluetooth --disable-dbus \
	--disable-rdma --disable-remote --without-dpdk >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null

cd /
rm -rf "$work"

# The mips targets are tier 3: cargo builds their std itself (-Zbuild-std, see
# Cross.toml), and a static link of that std asks for -lunwind. Rust ships the
# library with the prebuilt std of the other musl targets; here the unwinder
# is the one of GCC, under another name. /opt/libpcap/lib is on the link path.
case "$target" in
mips*)
	eh=$("$cc" -print-file-name=libgcc_eh.a)
	case "$eh" in
	/*)
		ln -s "$eh" /opt/libpcap/lib/libunwind.a
		echo "build-libpcap: libunwind.a -> $eh"
		;;
	*)
		echo "build-libpcap: no libgcc_eh.a in this toolchain" >&2
		exit 1
		;;
	esac
	;;
esac

# vendor/pcap/build.rs makes the same check to lay out struct pcap_pkthdr.
if printf '#include <sys/time.h>\n' | "$cc" -E -dM -x c - | grep -q _REDIR_TIME64; then
	echo "build-libpcap: $target C library uses a 64-bit time_t"
else
	echo "build-libpcap: $target C library uses a native-width time_t"
fi
ls -l /opt/libpcap/lib

#!/bin/sh
#
# Release notes header: which file to download and how to install it.
#
#   release-notes.sh <package version, e.g. 1.0.0> [dist dir]
#
# With [dist dir] (the release job passes the directory it is about to
# publish) the file names are taken from what is really there, and a missing
# package is an error: the release must not go out incomplete. Without it the
# names follow the convention of ci/package.sh and ci/linux-package.sh.

set -eu

v=${1:?usage: $0 <version> [dist dir]}
dist=${2:-}
r=${PKG_RELEASE:-1}

missing=0
# <variable> <glob in dist> <name by convention>: sets the variable to the
# real file name, or to the conventional one when there is no dist dir.
file() {
	_name=$3
	if [ -n "$dist" ]; then
		_name=
		for _f in "$dist"/$2; do
			[ -e "$_f" ] && _name=${_f##*/}
		done
		if [ -z "$_name" ]; then
			echo "release-notes: no file matching $2 in $dist" >&2
			missing=$((missing + 1))
			_name=$3
		fi
	fi
	eval "$1=\$_name"
}

for fam in x86_64 aarch64 armv7; do
	file "ipk_$fam" "gswifi_*_$fam.ipk" "gswifi_${v}_$fam.ipk"
	file "apk_$fam" "gswifi_*_$fam.apk" "gswifi_${v}_$fam.apk"
	file "tar_$fam" "gswifi-*-$fam-linux-musl.tar.gz" "gswifi-$v-$fam-linux-musl.tar.gz"
done
file ipk_luci 'luci-app-gswifi_*_all.ipk' "luci-app-gswifi_${v}_all.ipk"
file apk_luci 'luci-app-gswifi_*_all.apk' "luci-app-gswifi_${v}_all.apk"
file deb_amd64 'gswifi_*_amd64.deb' "gswifi_${v}-${r}_amd64.deb"
file deb_arm64 'gswifi_*_arm64.deb' "gswifi_${v}-${r}_arm64.deb"
file deb_armhf 'gswifi_*_armhf.deb' "gswifi_${v}-${r}_armhf.deb"
file rpm_x86_64 'gswifi-*.x86_64.rpm' "gswifi-${v}-${r}.x86_64.rpm"
file rpm_aarch64 'gswifi-*.aarch64.rpm' "gswifi-${v}-${r}.aarch64.rpm"
file rpm_armv7hl 'gswifi-*.armv7hl.rpm' "gswifi-${v}-${r}.armv7hl.rpm"

# The mipsel build is experimental and may be absent: mentioned only if it is
# in the release.
tar_mipsel=
if [ -n "$dist" ]; then
	for f in "$dist"/gswifi-*-mipsel-linux-musl.tar.gz; do
		[ -e "$f" ] && tar_mipsel=${f##*/}
	done
fi

if [ "$missing" != 0 ]; then
	echo "release-notes: $missing expected release file(s) missing" >&2
	exit 1
fi

# file() assigns the names used below.
# shellcheck disable=SC2154
cat <<EOF
## OpenWrt

### 下载哪个文件

先在路由器上查看架构：OpenWrt 24.10 及更早用 \`opkg print-architecture\`，25.12 及以后用 \`cat /etc/apk/arch\`。

| 路由器架构 | 常见设备 | OpenWrt 23.05 / 24.10（opkg） | OpenWrt 25.12 及以后（apk） |
|---|---|---|---|
| \`x86_64\` | 软路由、虚拟机 | \`$ipk_x86_64\` | \`$apk_x86_64\` |
| \`aarch64_*\` | MT798x (filogic)、IPQ807x、RK35xx、树莓派 3/4/5 | \`$ipk_aarch64\` | \`$apk_aarch64\` |
| \`arm_cortex-a*\` | IPQ40xx、MT7623、i.MX6、树莓派 2 等 ARMv7 设备 | \`$ipk_armv7\` | \`$apk_armv7\` |

每台路由器需要两个包：上表里对应架构的 \`gswifi\`（认证程序和服务），以及所有架构通用的网页界面 \`$ipk_luci\`（opkg）或 \`$apk_luci\`（apk）。装错架构的包会在安装时被拒绝。

这些包在 OpenWrt 23.05、24.10（ipk）和 25.12（apk）的官方 rootfs 里做过安装测试。MT7621 等 \`mipsel_24kc\` 设备目前没有安装包。

### 安装

把两个包上传到路由器的 \`/tmp\` 后：

\`\`\`sh
# OpenWrt 24.10 及更早（以 aarch64 为例）
opkg update
opkg install /tmp/$ipk_aarch64 /tmp/$ipk_luci

# OpenWrt 25.12 及以后（包没有签名，需要 --allow-untrusted）
apk update
apk add --allow-untrusted /tmp/$apk_aarch64 /tmp/$apk_luci
\`\`\`

然后刷新 LuCI，在 **服务 → 校园网认证** 里填写认证方式和账号并启用。

## 其他 Linux 发行版

### 下载哪个文件

先用 \`uname -m\` 查看架构：

| \`uname -m\` | Debian / Ubuntu 等（deb） | Fedora / RHEL / Rocky / openSUSE 等（rpm） |
|---|---|---|
| \`x86_64\` | \`$deb_amd64\` | \`$rpm_x86_64\` |
| \`aarch64\` | \`$deb_arm64\` | \`$rpm_aarch64\` |
| \`armv7l\` | \`$deb_armhf\` | \`$rpm_armv7hl\` |

程序是静态编译的，不依赖任何系统库，各发行版和版本通用。

### 安装

\`\`\`sh
# Debian / Ubuntu
sudo apt install ./$deb_amd64

# Fedora / RHEL / Rocky（包没有签名，dnf 会提示跳过签名检查）
sudo dnf install ./$rpm_x86_64
\`\`\`

然后在 \`/etc/gswifi/config.toml\` 里去掉 \`[[networks]]\` 一段的注释，填写网卡名称、认证方式、用户名和密码，再启动服务并设为开机自启：

\`\`\`sh
sudo systemctl enable --now gswifi
journalctl -u gswifi -f    # 查看运行日志
\`\`\`

掉线或认证服务器无响应时会自动重连；账号、密码或 MAC 绑定被拒绝时不会在同一个地址上反复重试，以免账号被锁定。改好配置后执行 \`sudo systemctl restart gswifi\`。

## 单独的可执行文件

\`$tar_x86_64\`、\`$tar_aarch64\`、\`$tar_armv7\` 里是单独的静态可执行文件 \`gswifi\`，不依赖 libpcap 和系统的 C 库，可在对应架构的任意 Linux 上直接运行。
EOF

if [ -n "$tar_mipsel" ]; then
	cat <<EOF

\`$tar_mipsel\` 是 **实验性** 的 mipsel（MT7621 等，软浮点）静态可执行文件：用 nightly 工具链构建，只在 qemu 里运行过，没有安装包。
EOF
fi

cat <<EOF

## 校验

\`SHA256SUMS\` 里是以上所有文件的 SHA-256：

\`\`\`sh
sha256sum -c SHA256SUMS --ignore-missing
\`\`\`
EOF

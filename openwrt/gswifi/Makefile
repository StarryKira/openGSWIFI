# SPDX-License-Identifier: MIT
#
# Open GSWIFI - multi-protocol campus network authentication client
#
# For building inside the OpenWrt SDK / buildroot with the packages feed's
# Rust support. The release packages are not made with this file: they are
# assembled from static binaries by ci/package.sh, which installs the same
# files to the same places (keep the two in step).

include $(TOPDIR)/rules.mk

PKG_NAME:=gswifi
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

# Builds the tagged release of this repository. Keep PKG_VERSION in step with
# Cargo.toml; ci/version.sh (the lint job) refuses a mismatch.
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/StarryKira/openGSWIFI.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=fuqiuluo
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/gswifi
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Open GSWIFI campus network authentication client
  URL:=https://github.com/StarryKira/openGSWIFI
  DEPENDS:=$(RUST_ARCH_DEPENDS) +libpcap +ucode +ucode-mod-fs +ucode-mod-uci +ucode-mod-ubus +jsonfilter
endef

define Package/gswifi/description
  Open GSWIFI authenticates against campus networks (Ruijie, Saier and
  standard 802.1X, H3C iNode and Portal, Anlang, Dr.com, Hubei Portal) and
  can normalise outgoing traffic against sharing detection with nftables.
  This package installs the client, a procd service driven by
  /etc/config/gswifi, and the helpers luci-app-gswifi talks to.
endef

define Package/gswifi/conffiles
/etc/config/gswifi
endef

# The vendored pcap crate probes the library from its build script. Point it at
# the target libpcap and state the API level instead of letting it dlopen a
# library on the build host. Every cfg the crate knows about is <= 1.9.1.
CARGO_PKG_VARS += \
	LIBPCAP_LIBDIR="$(STAGING_DIR)/usr/lib" \
	LIBPCAP_VER="1.9.1"

# The binary is one member of the workspace.
define Build/Compile
	$(call Build/Compile/Cargo,crates/gswifi)
endef

define Package/gswifi/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/gswifi $(1)/usr/bin/gswifi
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/gswifi.config $(1)/etc/config/gswifi
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/gswifi.init $(1)/etc/init.d/gswifi
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/gswifi.defaults $(1)/etc/uci-defaults/90_gswifi
	$(INSTALL_DIR) $(1)/usr/libexec/gswifi
	$(INSTALL_BIN) ./files/ctl.uc $(1)/usr/libexec/gswifi/ctl
	$(INSTALL_BIN) ./files/auth.sh $(1)/usr/libexec/gswifi/gswifi-auth
	$(INSTALL_BIN) ./files/proxy.sh $(1)/usr/libexec/gswifi/gswifi-proxy
	$(INSTALL_BIN) ./files/protect.sh $(1)/usr/libexec/gswifi/protect
	$(INSTALL_DIR) $(1)/usr/share/ucode/gswifi
	$(INSTALL_DATA) ./files/lib/*.uc $(1)/usr/share/ucode/gswifi/
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/ruleset-post
	$(INSTALL_DATA) ./files/gswifi.nft $(1)/usr/share/nftables.d/ruleset-post/90-gswifi.nft
endef

# The scripts below are the same as the ones ci/package.sh writes.
define Package/gswifi/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/gswifi enable
/etc/init.d/gswifi restart >/dev/null 2>&1
exit 0
endef

# Stopping takes the protect rules out (table, DNS fragment, kernel
# parameters); the firewall include goes with the package files.
define Package/gswifi/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/gswifi stop >/dev/null 2>&1
/etc/init.d/gswifi disable >/dev/null 2>&1
/usr/libexec/gswifi/protect remove >/dev/null 2>&1
exit 0
endef

define Package/gswifi/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
rm -rf /var/run/gswifi /var/etc/gswifi
rm -f /var/lock/gswifi-protect.lock
exit 0
endef

$(eval $(call BuildPackage,gswifi))

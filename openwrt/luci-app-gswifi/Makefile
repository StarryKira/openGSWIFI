# SPDX-License-Identifier: MIT

include $(TOPDIR)/rules.mk

PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_PO_VERSION:=$(PKG_VERSION)

LUCI_TITLE:=LuCI support for Open GSWIFI
LUCI_DESCRIPTION:=Status, settings, traffic normalisation (anti sharing detection), log and tools pages for the Open GSWIFI campus network client.
LUCI_DEPENDS:=+luci-base +rpcd +ucode +gswifi
LUCI_PKGARCH:=all

PKG_LICENSE:=MIT
PKG_MAINTAINER:=fuqiuluo

# No custom postinst: the default one from luci.mk clears the LuCI caches and
# sends rpcd a SIGHUP, which re-executes it and registers luci.gswifi.
# root/usr/libexec/rpcd/luci.gswifi must be executable in git: luci.mk copies
# the root/ tree with its modes.

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature

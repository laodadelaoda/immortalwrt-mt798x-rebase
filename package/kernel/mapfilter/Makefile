include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mapfilter
PKG_VERSION:=7.6.7.3
PKG_RELEASE:=1
PKG_SOURCE:=mapfilter-96f2afed.tar.bz2
PKG_SOURCE_URL:=@SF/mapfilter
PKG_HASH:=3928c6614b84e74f1f1762cee61de8e422299e792f5f363dc369dfc0ed0f1714
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define KernelPackage/mapfilter
  SUBMENU:=Network Support
  TITLE:=MTK MAP netfilter support
  KCONFIG:=CONFIG_MAP_FILTER_SUPPORT
  FILES:=$(PKG_BUILD_DIR)/mapfilter.ko
  AUTOLOAD:=$(call AutoLoad,50,mapfilter)
  DEPENDS:=+kmod-nf-conntrack +kmod-nf-nat
endef

define KernelPackage/mapfilter/description
  MTK MAP netfilter module. Required by p1905_managerd for
  MAP_SO_BASE and MAP_NETLINK socket options.
endef

define Build/Compile
$(MAKE) -C "$(LINUX_DIR)" \
$(KERNEL_MAKE_FLAGS) \
M="$(PKG_BUILD_DIR)" \
modules
endef

$(eval $(call KernelPackage,mapfilter))

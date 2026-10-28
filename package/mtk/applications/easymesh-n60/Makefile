include $(TOPDIR)/rules.mk

PKG_NAME:=easymesh-n60
PKG_VERSION:=7.6.7.3
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/easymesh-n60
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MTK EasyMesh binaries and config for N60 Pro
  DEPENDS:=+kmod-mapfilter +libnl-tiny
endef

define Package/easymesh-n60/description
  GL 7.6.7.3 EasyMesh binaries (wapp/mapd/p1905_managerd) with
  N60 Pro original configs and startup script.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/easymesh-n60/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/sbin $(1)/usr/lib $(1)/etc/map $(1)/etc/init.d $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/usr/bin/wapp $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/bin/mapd $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/bin/p1905_managerd $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/sbin/generate-mapd-strng $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/usr/lib/libeth_1905ops.so $(1)/usr/lib/
	$(INSTALL_BIN) ./files/usr/lib/libmapd_interface_client.so $(1)/usr/lib/
	$(INSTALL_DATA) ./files/usr/lib/libssl.so.1.1 $(1)/usr/lib/
	$(INSTALL_DATA) ./files/usr/lib/libcrypto.so.1.1 $(1)/usr/lib/
	ln -sf libnl-tiny.so.1 $(1)/usr/lib/libnl-tiny.so
	$(INSTALL_DATA) ./files/etc/map/mapd_cfg $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/map/mapd_user.cfg $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/map/1905d.cfg $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/map/wts_bss_info_config $(1)/etc/map/
	$(INSTALL_BIN) ./files/etc/init.d/easymesh $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/etc/uci-defaults/1001-easymesh-n60 $(1)/etc/uci-defaults/
endef

$(eval $(call BuildPackage,easymesh-n60))

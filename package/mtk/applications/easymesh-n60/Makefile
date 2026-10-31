include $(TOPDIR)/rules.mk

PKG_NAME:=easymesh-n60
PKG_VERSION:=7.6.7.3
PKG_RELEASE:=9

include $(INCLUDE_DIR)/package.mk

define Package/easymesh-n60
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MTK EasyMesh binaries and config for N60 Pro
  DEPENDS:=+kmod-mapfilter +libnl-tiny +libkvcutil
endef

define Package/easymesh-n60/description
  GL 7.6.7.3 EasyMesh binaries (wapp/mapd/p1905_managerd) with
  N60 Pro original configs and startup script.
endef

define Build/Prepare
	set -eu; \
	printf '%s  %s\n' '73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462' '$(DL_DIR)/wappd-80ca5724.tar.bz2' | sha256sum -c -; \
	mkdir -p $(PKG_BUILD_DIR); \
	tar -xjf '$(DL_DIR)/wappd-80ca5724.tar.bz2' -C $(PKG_BUILD_DIR) \
		wappd/config_and_icon_files/wapp_ap_ra0_default.conf \
		wappd/config_and_icon_files/wapp_ap_rax0_default.conf; \
	sed -i 's/^interworking=1/interworking=0/' '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_ra0_default.conf'; \
	sed -i '/^mbo_ap_cdcp=/d; /^mbo_ap_assoc_disallow_reason=/d; /^mbo_ap_assoc_retry_delay=/d; /^mbo_ap_transition_reason_code=/d; /^mbo_ap_capability=/d' '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_ra0_default.conf'; \
	printf '\n# MediaTek MBO parameters for N60 Pro\nmbo_ap_cdcp=1\nmbo_ap_assoc_disallow_reason=0\nmbo_ap_assoc_retry_delay=0\nmbo_ap_transition_reason_code=0\nmbo_ap_capability=64\n' >> '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_ra0_default.conf'; \
	sed -i 's/^interworking=1/interworking=0/' '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_rax0_default.conf'; \
	sed -i '/^mbo_ap_cdcp=/d; /^mbo_ap_assoc_disallow_reason=/d; /^mbo_ap_assoc_retry_delay=/d; /^mbo_ap_transition_reason_code=/d; /^mbo_ap_capability=/d' '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_rax0_default.conf'; \
	printf '\n# MediaTek MBO parameters for N60 Pro\nmbo_ap_cdcp=1\nmbo_ap_assoc_disallow_reason=0\nmbo_ap_assoc_retry_delay=0\nmbo_ap_transition_reason_code=0\nmbo_ap_capability=64\n' >> '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_rax0_default.conf'; \
	printf 'conf_list=/etc/wapp_ap_ra0.conf;/etc/wapp_ap_rax0.conf;\n' > $(PKG_BUILD_DIR)/wapp_ap.conf
endef

define Build/Compile
endef

define Package/easymesh-n60/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/sbin $(1)/usr/lib $(1)/etc $(1)/etc/map $(1)/etc/init.d $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/usr/bin/wapp $(1)/usr/bin/
	if [ -s ./files/usr/bin/wappctrl ]; then \
		$(INSTALL_BIN) ./files/usr/bin/wappctrl $(1)/usr/bin/; \
	fi
	$(INSTALL_BIN) ./files/usr/bin/mapd $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/bin/p1905_managerd $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/bin/wapp-n60-wrapper $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/sbin/generate-mapd-strng $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/usr/sbin/generate-wts-bss-info $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/usr/lib/libeth_1905ops.so $(1)/usr/lib/
	$(INSTALL_BIN) ./files/usr/lib/libmapd_interface_client.so $(1)/usr/lib/
	$(INSTALL_DATA) ./files/usr/lib/libssl.so.1.1 $(1)/usr/lib/
	$(INSTALL_DATA) ./files/usr/lib/libcrypto.so.1.1 $(1)/usr/lib/
	ln -sf libnl-tiny.so.1 $(1)/usr/lib/libnl-tiny.so
	$(INSTALL_DATA) ./files/etc/map/mapd_cfg $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/map/mapd_user.cfg $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/map/1905d.cfg $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/map/wts_bss_info_config $(1)/etc/map/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wapp_ap.conf $(1)/etc/wapp_ap.conf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_ra0_default.conf $(1)/etc/wapp_ap_ra0.conf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_rax0_default.conf $(1)/etc/wapp_ap_rax0.conf
	$(INSTALL_BIN) ./files/etc/init.d/easymesh $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/etc/uci-defaults/1001-easymesh-n60 $(1)/etc/uci-defaults/
endef

$(eval $(call BuildPackage,easymesh-n60))

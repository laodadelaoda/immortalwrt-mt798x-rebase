include $(TOPDIR)/rules.mk

PKG_NAME:=easymesh-n60
PKG_VERSION:=7.6.7.3
PKG_RELEASE:=14
PKG_BUILD_DEPENDS:=datconf openssl libnl-tiny
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/easymesh-n60
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MTK EasyMesh binaries and config for N60 Pro
  DEPENDS:=+kmod-mapfilter +libnl-tiny +libkvcutil +libopenssl
endef

define Package/easymesh-n60/description
  Source-built MediaTek 7.6.7.3 WAPP/MAPD/P1905 EasyMesh stack for N60 Pro,
  using the matching vendor source archives and N60-specific runtime configs.
endef

define Build/Prepare
	set -eu; \
	mkdir -p $(PKG_BUILD_DIR); \
	printf '%s  %s\n' '73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462' '$(DL_DIR)/wappd-80ca5724.tar.bz2' | sha256sum -c -; \
	printf '%s  %s\n' '39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18' '$(DL_DIR)/mapd-6eca4331.tar.bz2' | sha256sum -c -; \
	printf '%s  %s\n' '82f7cc4ad5731e750f87c9a4ad19a39d2456bb8fec0cf79bf4b3f3ccb4f14795' '$(DL_DIR)/1905daemon-35234223.tar.bz2' | sha256sum -c -; \
	printf '%s  %s\n' 'd325b4a8dc2bf44bd3bd639a0c300380c0a6240f407807f8f2eea80d006c8dba' '$(DL_DIR)/libmapd-0132d199.tar.bz2' | sha256sum -c -; \
	tar -xjf '$(DL_DIR)/wappd-80ca5724.tar.bz2' -C $(PKG_BUILD_DIR); \
	tar -xjf '$(DL_DIR)/mapd-6eca4331.tar.bz2' -C $(PKG_BUILD_DIR); \
	tar -xjf '$(DL_DIR)/1905daemon-35234223.tar.bz2' -C $(PKG_BUILD_DIR); \
	tar -xjf '$(DL_DIR)/libmapd-0132d199.tar.bz2' -C $(PKG_BUILD_DIR); \
	python3 -c 'from pathlib import Path; p=Path("$(PKG_BUILD_DIR)/libmapd/include/os.h"); s=p.read_text(encoding="utf-8"); old="os_memset(&now, 0, sizeof(now))"; assert s.count(old)==1, "expected exactly one os_memset call in libmapd/include/os.h"; s=s.replace(old, "memset(&now, 0, sizeof(now))", 1); lines=s.splitlines(True); lines.insert(0, "#include <string.h>"+chr(10)) if "#include <string.h>" not in s else None; p.write_text("".join(lines), encoding="utf-8"); print("Applied libmapd os_memset portability fix:", p)'; \
	tr -d '\r' < '$(PKG_BUILD_DIR)/1905daemon/ethernet/mediatek_DSA/eth_ops_dsa.c' > '$(PKG_BUILD_DIR)/1905daemon/ethernet/mediatek_DSA/eth_ops_dsa.c.tmp'; \
	mv '$(PKG_BUILD_DIR)/1905daemon/ethernet/mediatek_DSA/eth_ops_dsa.c.tmp' '$(PKG_BUILD_DIR)/1905daemon/ethernet/mediatek_DSA/eth_ops_dsa.c'; \
	patch -d $(PKG_BUILD_DIR)/1905daemon -p1 < ./patches/001-dsa-use-linux-mii-ioctl.patch; \
	sed -i 's/^interworking=1/interworking=0/' '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_ra0_default.conf'; \
	sed -i '/^mbo_ap_cdcp=/d; /^mbo_ap_assoc_disallow_reason=/d; /^mbo_ap_assoc_retry_delay=/d; /^mbo_ap_transition_reason_code=/d; /^mbo_ap_capability=/d' '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_ra0_default.conf'; \
	printf '\n# MediaTek MBO parameters for N60 Pro\nmbo_ap_cdcp=1\nmbo_ap_assoc_disallow_reason=0\nmbo_ap_assoc_retry_delay=0\nmbo_ap_transition_reason_code=0\nmbo_ap_capability=64\n' >> '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_ra0_default.conf'; \
	sed -i 's/^interworking=1/interworking=0/' '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_rax0_default.conf'; \
	sed -i '/^mbo_ap_cdcp=/d; /^mbo_ap_assoc_disallow_reason=/d; /^mbo_ap_assoc_retry_delay=/d; /^mbo_ap_transition_reason_code=/d; /^mbo_ap_capability=/d' '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_rax0_default.conf'; \
	printf '\n# MediaTek MBO parameters for N60 Pro\nmbo_ap_cdcp=1\nmbo_ap_assoc_disallow_reason=0\nmbo_ap_assoc_retry_delay=0\nmbo_ap_transition_reason_code=0\nmbo_ap_capability=64\n' >> '$(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_rax0_default.conf'; \
	printf 'conf_list=/etc/wapp_ap_ra0.conf;/etc/wapp_ap_rax0.conf;\n' > $(PKG_BUILD_DIR)/wappd/wapp_ap.conf; \
	python3 -c 'import re; from pathlib import Path; d=chr(36); files=[Path("$(PKG_BUILD_DIR)/1905daemon/ethernet/Makefile"), Path("$(PKG_BUILD_DIR)/1905daemon/ethernet/mediatek_DSA/libbridge/Makefile")]; pat=re.compile(re.escape(d+"(CC)")+r"\s+"+re.escape(d+"(CFLAGS)") + r"(?!\s+"+re.escape(d+"(EXTRA_CFLAGS)") + r")"); [(lambda p,t,n: (p.write_text(pat.sub(lambda m:m.group(0)+" "+d+"(EXTRA_CFLAGS)",t), encoding="utf-8"), print("Updated compiler rules:",p,"count=",n)) if n else print("Compiler rules already expansion-safe:",p))(p,p.read_text(encoding="utf-8"),len(pat.findall(p.read_text(encoding="utf-8")))) for p in files]'
endef

define Build/Compile
	set -eu; \
	TARGET_EASYMESH_CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -Wno-deprecated-declarations"; \
	OPENWRT_EASYMESH_CFLAGS="$$$$TARGET_EASYMESH_CFLAGS -DCONFIG_SUPPORT_OPENWRT"; \
	WAPP_UAPI_DIR="$(LINUX_DIR)/include/uapi/linux/wapp"; \
	test -s "$$$$WAPP_UAPI_DIR/wapp_cmm_type.h" || { echo "Missing MTK WAPP UAPI header: $$$$WAPP_UAPI_DIR/wapp_cmm_type.h" >&2; exit 1; }; \
	test -s "$$$$WAPP_UAPI_DIR/mt_wlan_cmm_oid.h" || { echo "Missing MTK WAPP OID header: $$$$WAPP_UAPI_DIR/mt_wlan_cmm_oid.h" >&2; exit 1; }; \
	$(MAKE) -C $(PKG_BUILD_DIR)/libmapd \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -Werror -g" \
		all; \
	$(MAKE) -C $(PKG_BUILD_DIR)/wappd \
		TOPDIR="$(TOPDIR)" UAPD_INCLUDE_PATH="$$$$WAPP_UAPI_DIR" CONFIG_SUPPORT_OPENWRT=y CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y \
		CC="$(TARGET_CC)" EXTRA_CFLAGS="$$$$TARGET_EASYMESH_CFLAGS" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib -lpthread -ldatconf -lkvcutil -lssl -lcrypto" \
		all; \
	mkdir -p $(PKG_BUILD_DIR)/1905daemon/obj; \
	EXTRA_CFLAGS="$$$$OPENWRT_EASYMESH_CFLAGS" $(MAKE) -C $(PKG_BUILD_DIR)/1905daemon \
		TOPDIR="$(TOPDIR)" ROOTDIR="$(TOPDIR)" \
		LINUXDIR="$(patsubst $(TOPDIR)/%,%,$(LINUX_DIR))" \
		STAGING_DIR="$(STAGING_DIR)" \
		CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y MAP_R3_SUPPORT=y SWTICH_DSA_ARCH=y \
		CC="$(TARGET_CC)" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib -Wl,--no-as-needed -lpthread -lnl-tiny -lssl -lcrypto" \
		all; \
	$(MAKE) -C $(PKG_BUILD_DIR)/mapd \
		TOPDIR="$(TOPDIR)" CONFIG_SUPPORT_OPENWRT=y CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y \
		CC="$(TARGET_CC)" LDO="$(TARGET_CC)" \
		EXTRA_CFLAGS="$$$$OPENWRT_EASYMESH_CFLAGS" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib" \
		version mapd; \
	test -x $(PKG_BUILD_DIR)/wappd/wapp; \
	test -x $(PKG_BUILD_DIR)/wappd/wappctrl; \
	test -x $(PKG_BUILD_DIR)/mapd/mapd; \
	test -x $(PKG_BUILD_DIR)/1905daemon/p1905_managerd; \
	test -s $(PKG_BUILD_DIR)/1905daemon/ethernet/libeth_1905ops.so; \
	test -s $(PKG_BUILD_DIR)/libmapd/libmapd_interface_client.so
endef

define Package/easymesh-n60/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/sbin $(1)/usr/lib $(1)/etc $(1)/etc/map $(1)/etc/init.d $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wappd/wapp $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wappd/wappctrl $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mapd/mapd $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/1905daemon/p1905_managerd $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/bin/wapp-n60-wrapper $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/sbin/generate-mapd-strng $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/usr/sbin/easymesh-n60-diagnose $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/usr/sbin/easymesh-n60-validate-wts $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/1905daemon/ethernet/libeth_1905ops.so $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libmapd/libmapd_interface_client.so $(1)/usr/lib/
	ln -sf libnl-tiny.so.1 $(1)/usr/lib/libnl-tiny.so
	$(INSTALL_DATA) ./files/etc/map/mapd_cfg $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/map/mapd_user.cfg $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/map/1905d.cfg $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/map/wts_bss_info_config $(1)/etc/map/
	$(INSTALL_DATA) ./files/etc/ethernet_cfg.txt $(1)/etc/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wapp_ap.conf $(1)/etc/wapp_ap.conf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_ra0_default.conf $(1)/etc/wapp_ap_ra0.conf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wappd/config_and_icon_files/wapp_ap_rax0_default.conf $(1)/etc/wapp_ap_rax0.conf
	$(INSTALL_BIN) ./files/etc/init.d/easymesh $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/etc/uci-defaults/1001-easymesh-n60 $(1)/etc/uci-defaults/
endef

$(eval $(call BuildPackage,easymesh-n60))

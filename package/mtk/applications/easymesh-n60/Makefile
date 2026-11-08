include $(TOPDIR)/rules.mk

PKG_NAME:=easymesh-n60
PKG_VERSION:=7.6.7.3
PKG_RELEASE:=27
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

# Canonical lock owns archive hashes; verify before extracting any vendor source.
define Build/Prepare
	set -eu; \
	python3 ./scripts/n60-vendor-source-transforms.py verify-lock "$(TOPDIR)" --downloads "$(DL_DIR)"; \
	apply_patch_strict() { \
		patch_file="$$$$1"; patch_root="$$$$2"; \
		test -s "$$$$patch_file" || { echo "Missing patch: $$$$patch_file" >&2; exit 1; }; \
		patch --dry-run --batch --forward --fuzz=0 -d "$$$$patch_root" -p1 < "$$$$patch_file"; \
		patch --batch --forward --fuzz=0 -d "$$$$patch_root" -p1 < "$$$$patch_file"; \
	}; \
	printf '%s\n' 'Checking N60 MT Wi-Fi / EasyMesh 7.6.7.3 compatibility lock'; \
	grep -qx 'CONFIG_MTK_MT_WIFI_DRIVER_VERSION_7673=y' $(TOPDIR)/.config || { echo "N60 EasyMesh requires MT Wi-Fi driver 7.6.7.3" >&2; exit 1; }; \
	grep -qx 'CONFIG_MTK_MAP_SUPPORT=y' $(TOPDIR)/.config || { echo "N60 EasyMesh requires MTK MAP support" >&2; exit 1; }; \
	grep -qx 'CONFIG_MTK_MAP_R2_VER_SUPPORT=y' $(TOPDIR)/.config || { echo "N60 EasyMesh requires MTK MAP R2 support" >&2; exit 1; }; \
	grep -qx 'CONFIG_MTK_MAP_R3_VER_SUPPORT=y' $(TOPDIR)/.config || { echo "N60 EasyMesh requires MTK MAP R3 support" >&2; exit 1; }; \
	DRIVER_MAKEFILE="$(TOPDIR)/package/mtk/drivers/mt_wifi/Makefile"; \
	grep -Fqx 'PKG_VERSION:=7.6.7.3' "$$$$DRIVER_MAKEFILE" || { echo "MT Wi-Fi 7.6.7.3 package version declaration missing" >&2; exit 1; }; \
	rm -rf $(PKG_BUILD_DIR); mkdir -p $(PKG_BUILD_DIR); \
	tar -xjf '$(DL_DIR)/wappd-80ca5724.tar.bz2' -C $(PKG_BUILD_DIR); \
	tar -xjf '$(DL_DIR)/mapd-6eca4331.tar.bz2' -C $(PKG_BUILD_DIR); \
	tar -xjf '$(DL_DIR)/1905daemon-35234223.tar.bz2' -C $(PKG_BUILD_DIR); \
	tar -xjf '$(DL_DIR)/libmapd-0132d199.tar.bz2' -C $(PKG_BUILD_DIR); \
	patch_names="$$$$(python3 ./scripts/n60-vendor-lock.py patch-order --repo "$(TOPDIR)" --set easymesh --phase application)"; \
	test -n "$$$$patch_names" || { echo "EasyMesh application patch order is empty in vendor Lock" >&2; exit 1; }; \
	printf "LOCK APPLICATION PATCH: %s\\n" "$$$$patch_names"; \
	for patch_name in $$$$patch_names; do apply_patch_strict "./patches/$$$$patch_name" "$(PKG_BUILD_DIR)"; done; \
	python3 ./scripts/n60-vendor-source-transforms.py normalize "$(PKG_BUILD_DIR)"; \
	WAPP_WTS_SRC="$(PKG_BUILD_DIR)/wappd/common/main.c"; \
	P1905_WTS_SRC="$(PKG_BUILD_DIR)/1905daemon/src/file_io.c"; \
	grep -Fq 'if (i >= content_len - 1)' "$$$$WAPP_WTS_SRC" || { echo "WAPP WTS input bound missing after patch" >&2; exit 1; }; \
	grep -Fq 'os_strlen(pos1) >= sizeof(key)' "$$$$WAPP_WTS_SRC" || { echo "WAPP WTS key field bound missing after patch" >&2; exit 1; }; \
	grep -Fq "content[i] = '\\0';" "$$$$P1905_WTS_SRC" || { echo "P1905 WTS buffer terminator missing after patch" >&2; exit 1; }; \
	for src in "$$$$WAPP_WTS_SRC" "$(PKG_BUILD_DIR)/wappd/common/wdev.c" "$(PKG_BUILD_DIR)/wappd/map/map_1905.c" "$$$$P1905_WTS_SRC" "$(PKG_BUILD_DIR)/1905daemon/src/multi_ap.c" "$(PKG_BUILD_DIR)/mapd/src/topologySrv/topologySrv.c"; do \
		if grep -Eq 'key=%s|psk = %s' "$$$$src"; then echo "Wi-Fi secret logging remains in $$$$src" >&2; exit 1; fi; \
	done; \
	printf '%s\\n' 'PASS: WTS vendor parser security patch applied; bounded reads/fields, fail-closed errors and secret-log redaction verified.'; \
	patch_names="$$$$(python3 ./scripts/n60-vendor-lock.py patch-order --repo "$(TOPDIR)" --set easymesh --phase post_normalize)"; \
	test -n "$$$$patch_names" || { echo "EasyMesh post-normalize patch order is empty in vendor Lock" >&2; exit 1; }; \
	printf "LOCK POST-NORMALIZE PATCH: %s\\n" "$$$$patch_names"; \
	for patch_name in $$$$patch_names; do \
		patch_root_suffix="$$$$(python3 ./scripts/n60-vendor-lock.py patch-root --repo "$(TOPDIR)" --set easymesh --phase post_normalize --name "$$$$patch_name")"; \
		patch_root="$(PKG_BUILD_DIR)"; \
		if [ -n "$$$$patch_root_suffix" ]; then patch_root="$$$$patch_root/$$$$patch_root_suffix"; fi; \
		printf "LOCK POST-NORMALIZE ROOT: %s -> %s\n" "$$$$patch_name" "$$$$patch_root"; \
		apply_patch_strict "./patches/$$$$patch_name" "$$$$patch_root"; \
	done; \
	python3 ./scripts/n60-vendor-source-transforms.py finalize "$(PKG_BUILD_DIR)"; \
	python3 ./tests/test-dpp-source-contract.py $(PKG_BUILD_DIR); \
	python3 ./tests/test-easymesh-static-contract.py $(PKG_BUILD_DIR) $(TOPDIR); \
	python3 ./tests/test-wapp-map-buffer-contract.py $(PKG_BUILD_DIR); \
	python3 ./tests/test-vendor-artifact-inventory.py $(PKG_BUILD_DIR) $(TOPDIR)
endef

define Build/Compile
	set -eu; \
	TARGET_EASYMESH_CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -Wno-error=deprecated-declarations"; \
	OPENWRT_EASYMESH_CFLAGS="$$$$TARGET_EASYMESH_CFLAGS -DCONFIG_SUPPORT_OPENWRT"; \
	WAPP_UAPI_DIR="$(LINUX_DIR)/include/uapi/linux/wapp"; \
	test -s "$$$$WAPP_UAPI_DIR/wapp_cmm_type.h" || { echo "Missing MTK WAPP UAPI header: $$$$WAPP_UAPI_DIR/wapp_cmm_type.h" >&2; exit 1; }; \
	test -s "$$$$WAPP_UAPI_DIR/mt_wlan_cmm_oid.h" || { echo "Missing MTK WAPP OID header: $$$$WAPP_UAPI_DIR/mt_wlan_cmm_oid.h" >&2; exit 1; }; \
	$(MAKE) -C $(PKG_BUILD_DIR)/libmapd \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -Werror -g" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		all; \
	test -s "$(STAGING_DIR)/usr/include/openssl/x509.h" || { echo "Missing target OpenSSL headers: $(STAGING_DIR)/usr/include/openssl/x509.h" >&2; exit 1; }; \
	OPENSSL_VERSION_HEADER="$(STAGING_DIR)/usr/include/openssl/opensslv.h"; \
	test -s "$$$$OPENSSL_VERSION_HEADER" || { echo "Missing target OpenSSL version header: $$$$OPENSSL_VERSION_HEADER" >&2; exit 1; }; \
	grep -Eq '^[[:space:]]*#[[:space:]]*define[[:space:]]+OPENSSL_VERSION_MAJOR[[:space:]]+3([[:space:]]|$$$$)' "$$$$OPENSSL_VERSION_HEADER" || { echo "EasyMesh requires target OpenSSL major version 3" >&2; grep -E "OPENSSL_VERSION_(MAJOR|NUMBER)" "$$$$OPENSSL_VERSION_HEADER" >&2 || true; exit 1; }; \
	WAPP_COMPILE_LOG="$(PKG_BUILD_DIR)/wapp-compile.log"; \
	$(MAKE) -C $(PKG_BUILD_DIR)/wappd \
		TOPDIR="$(TOPDIR)" UAPD_INCLUDE_PATH="$(LINUX_DIR)/include/uapi/linux/wapp -I$(STAGING_DIR)/usr/include" CONFIG_SUPPORT_OPENWRT=y CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y \
		CC="$(TARGET_CC)" EXTRA_CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -Wno-error=deprecated-declarations -I$(LINUX_DIR)/include/uapi/linux/wapp" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib -lpthread -ldatconf -lkvcutil -lssl -lcrypto" \
		V=s all > "$$$$WAPP_COMPILE_LOG" 2>&1 || { cat "$$$$WAPP_COMPILE_LOG"; exit 1; }; \
	if grep -Eq '(^|: )error:|make(\[[0-9]+\])?: \*\*\*' "$$$$WAPP_COMPILE_LOG"; then cat "$$$$WAPP_COMPILE_LOG"; echo "WAPP compiler log contains an error despite a successful make status" >&2; exit 1; fi; \
	cat "$$$$WAPP_COMPILE_LOG"; \
	grep -F 'common/main.c' "$$$$WAPP_COMPILE_LOG" | grep -Fq -- '-Werror' || { echo "WAPP compile command lost -Werror" >&2; exit 1; }; \
	grep -F 'common/main.c' "$$$$WAPP_COMPILE_LOG" | grep -Fq -- '-Wno-error=deprecated-declarations' || { echo "WAPP deprecated-API diagnostics are not explicitly visible as non-fatal warnings" >&2; exit 1; }; \
	! grep -Fq -- '-Wno-deprecated-declarations' "$$$$WAPP_COMPILE_LOG" || { echo "WAPP must not suppress deprecated-API diagnostics" >&2; exit 1; }; \
	! grep -Fq 'unused-but-set-variable' "$$$$WAPP_COMPILE_LOG" || { echo "WAPP still emits an unused-but-set-variable diagnostic after the DPP source fix" >&2; exit 1; }; \
	echo "PASS: WAPP common/main.c compiled with -Werror; deprecated-API warnings remain visible and non-fatal."; \
	mkdir -p $(PKG_BUILD_DIR)/1905daemon/obj; \
	P1905_COMPILE_LOG="$(PKG_BUILD_DIR)/p1905-compile.log"; \
	EXTRA_CFLAGS="$$$$OPENWRT_EASYMESH_CFLAGS" $(MAKE) -C $(PKG_BUILD_DIR)/1905daemon \
		TOPDIR="$(TOPDIR)" ROOTDIR="$(TOPDIR)" \
		LINUXDIR="$(patsubst $(TOPDIR)/%,%,$(LINUX_DIR))" \
		STAGING_DIR="$(STAGING_DIR)" \
		CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y MAP_R3_SUPPORT=y SWTICH_DSA_ARCH=y \
		CC="$(TARGET_CC)" AR="$(TARGET_AR)" RANLIB="$(TARGET_RANLIB)" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib -Wl,--no-as-needed -lpthread -lnl-tiny -lssl -lcrypto" \
		all > "$$$$P1905_COMPILE_LOG" 2>&1 || { cat "$$$$P1905_COMPILE_LOG"; exit 1; }; \
	if grep -Eq '(^|: )error:|make(\[[0-9]+\])?: \*\*\*' "$$$$P1905_COMPILE_LOG"; then cat "$$$$P1905_COMPILE_LOG"; echo "P1905 compiler log contains an error despite a successful make status" >&2; exit 1; fi; \
	cat "$$$$P1905_COMPILE_LOG"; \
	MAPD_COMPILE_LOG="$(PKG_BUILD_DIR)/mapd-compile.log"; \
	$(MAKE) -C $(PKG_BUILD_DIR)/mapd \
		TOPDIR="$(TOPDIR)" CONFIG_SUPPORT_OPENWRT=y CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y \
		CC="$(TARGET_CC)" LDO="$(TARGET_CC)" \
		EXTRA_CFLAGS="$$$$OPENWRT_EASYMESH_CFLAGS" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib" \
		version mapd > "$$$$MAPD_COMPILE_LOG" 2>&1 || { cat "$$$$MAPD_COMPILE_LOG"; exit 1; }; \
	if grep -Eq '(^|: )error:|make(\[[0-9]+\])?: \*\*\*' "$$$$MAPD_COMPILE_LOG"; then cat "$$$$MAPD_COMPILE_LOG"; echo "MAPD compiler log contains an error despite a successful make status" >&2; exit 1; fi; \
	cat "$$$$MAPD_COMPILE_LOG"; \
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

# EasyMesh patch 021 review: WAPP wireless-mode capability macros

## Failure evidence

Quick Action #124 (42575724452, commit 4655455f07209367230c81291b5d06a0f2422129) passed the fixed-vendor patch audit and native Package Prepare, then failed during the actual WAPP compile:

- wappd/common/dot11v_btm.c:635: implicit declaration of WMODE_CAP_5G
- wappd/common/dot11v_btm.c:640: implicit declaration of WMODE_CAP_2G

The pinned WAPP source archive contains both macros in wappd/include/wdev.h, but places all three capability macros inside #ifdef MAP_6E_SUPPORT. The normal N60 Pro MAP R2/R3 build does not define MAP_6E_SUPPORT, because the WAPP Makefile enables it only when CONFIG_MTK_MAP_R2_6E_SUPPORT=y. The BTM path nevertheless uses the 2.4/5 GHz helpers in the non-6E build.

## Minimal correction

Patch 021 moves only WMODE_CAP_5G and WMODE_CAP_2G outside the 6 GHz conditional. WMODE_CAP_6G remains inside #ifdef MAP_6E_SUPPORT. No bit masks, vendor archive URL, source SHA256, Lock source identity, 6 GHz configuration, DSA, PCIe, PPE, or previously passing DPP/MAP buffer patches are changed.

## Regression gate

test-wapp-wireless-mode-contract.py checks the post-patch header, verifies that the WAPP Makefile still gates 6 GHz support behind CONFIG_MTK_MAP_R2_6E_SUPPORT, and rejects an N60 Pro config that enables that option. Native Build/Prepare runs this check before compilation. Final acceptance still requires the full fixed-vendor audit and a real GCC 14 WAPP/EasyMesh compile and link.

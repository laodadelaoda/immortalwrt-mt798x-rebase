#!/usr/bin/env python3
"""Linux 6.12 phylink/PCS and MediaTek WED lifecycle/API contracts."""
from pathlib import Path
import re
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: test-phy-wed-api.py <prepared-linux-source>")

root = Path(sys.argv[1])
failures = []

def check(ok, message):
    if not ok:
        failures.append(message)

def read(rel):
    path = root / rel
    if not path.is_file():
        failures.append("missing prepared source: " + rel)
        return ""
    return path.read_text(errors="replace")

def body(text, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", text, re.S)
    if not match:
        return ""
    start = text.find("{", match.start())
    depth = 0
    for pos in range(start, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    return ""

# Linux 6.12 phylink callback and decoder API contracts after selected backports.
phylink_h = read("include/linux/phylink.h")
check(bool(re.search(
    r"pcs_get_state\\s*\\)\\s*\\(\\s*struct phylink_pcs\\s*\\*\\s*pcs\\s*,\\s*"
    r"struct phylink_link_state\\s*\\*\\s*state",
    phylink_h, re.S)),
    "phylink_pcs_ops pcs_get_state callback does not match the Linux 6.12 two-argument contract")
check(bool(re.search(
    r"phylink_mii_c22_pcs_decode_state\\s*\\(\\s*struct phylink_link_state\\s*\\*\\s*state\\s*,\\s*"
    r"u16\\s+bmsr\\s*,\\s*u16\\s+lpa", phylink_h, re.S)),
    "phylink_mii_c22_pcs_decode_state signature is incompatible with Linux 6.12")

# SGMII PCS: cache, MMIO and workqueue state share regmap_lock.
lynxi = read("drivers/net/pcs/pcs-mtk-lynxi.c")
lynxi_status = body(lynxi, "mtk_pcs_lynxi_link_status")
lynxi_update = body(lynxi, "mtk_pcs_lynxi_update_state")
lynxi_get = body(lynxi, "mtk_pcs_lynxi_get_state")
lynxi_poll = body(lynxi, "mtk_pcs_lynxi_link_poll")
lynxi_enable = body(lynxi, "mtk_pcs_lynxi_enable")
lynxi_disable = body(lynxi, "mtk_pcs_lynxi_disable")
check(bool(re.search(
    r"mtk_pcs_lynxi_get_state\\s*\\(\\s*struct phylink_pcs\\s*\\*\\s*pcs\\s*,\\s*"
    r"struct phylink_link_state\\s*\\*\\s*state", lynxi, re.S)),
    "SGMII PCS get_state callback does not match Linux 6.12 phylink_pcs_ops")
check(bool(re.search(
    r"phylink_mii_c22_pcs_decode_state\\s*\\(\\s*&state\\s*,\\s*FIELD_GET", lynxi, re.S)),
    "SGMII PCS decoder call passes arguments incompatible with Linux 6.12")
check("if (regmap_read" in lynxi_status and "val = 0" in lynxi_status and
      "mutex_unlock(&mpcs->regmap_lock)" in lynxi_status,
      "SGMII link-status read does not map regmap failure to link-down")
check("state.link = false" in lynxi_update and "state->link = false" not in lynxi_update and
      "mutex_unlock(&mpcs->regmap_lock)" in lynxi_update and
      "mtk_pcs_lynxi_store_mpcs_state(mpcs, &state)" in lynxi_update,
      "SGMII update-state error path has a pointer/member error or leaks regmap_lock")
check(lynxi_update.find("mutex_lock(&mpcs->regmap_lock)") <
      lynxi_update.find("state = mpcs->state") and
      lynxi_update.rfind("mtk_pcs_lynxi_store_mpcs_state") <
      lynxi_update.rfind("mutex_unlock(&mpcs->regmap_lock)"),
      "SGMII cached link state is copied or published outside regmap_lock")
check(lynxi_get.find("mutex_lock(&mpcs->regmap_lock)") <
      lynxi_get.find("linkmode_copy") <
      lynxi_get.find("mtk_pcs_lynxi_load_mpcs_state") <
      lynxi_get.find("mutex_unlock(&mpcs->regmap_lock)"),
      "SGMII get_state accesses cached advertising/state without regmap_lock")
check("READ_ONCE(mpcs->poll)" in lynxi_poll and
      "WRITE_ONCE(mpcs->poll, true)" in lynxi_enable and
      "WRITE_ONCE(mpcs->poll, false)" in lynxi_disable and
      lynxi_disable.find("WRITE_ONCE(mpcs->poll, false)") <
      lynxi_disable.find("cancel_delayed_work_sync") and
      "mpcs->poll = false" in lynxi,
      "SGMII poll flag is not accessed with ordered READ_ONCE/WRITE_ONCE lifecycle")

# USXGMII PCS follows the same cache and delayed-work contract.
usx = read("drivers/net/pcs/pcs-mtk-usxgmii.c")
usx_update = body(usx, "mtk_usxgmii_pcs_update_state")
usx_get = body(usx, "mtk_usxgmii_pcs_get_state")
usx_poll = body(usx, "mtk_usxgmii_pcs_link_poll")
usx_enable = body(usx, "mtk_usxgmii_pcs_enable")
usx_disable = body(usx, "mtk_usxgmii_pcs_disable")
check(bool(re.search(
    r"mtk_usxgmii_pcs_get_state\\s*\\(\\s*struct phylink_pcs\\s*\\*\\s*pcs\\s*,\\s*"
    r"struct phylink_link_state\\s*\\*\\s*state", usx, re.S)),
    "USXGMII PCS get_state callback does not match Linux 6.12 phylink_pcs_ops")
check(usx_update.find("mutex_lock(&mpcs->regmap_lock)") <
      usx_update.find("state = mpcs->state") and
      usx_update.rfind("mtk_usxgmii_pcs_store_mpcs_state") <
      usx_update.rfind("mutex_unlock(&mpcs->regmap_lock)"),
      "USXGMII cached link state is copied or published outside regmap_lock")
check(usx_get.find("mutex_lock(&mpcs->regmap_lock)") <
      usx_get.find("mtk_usxgmii_pcs_load_mpcs_state") <
      usx_get.find("mutex_unlock(&mpcs->regmap_lock)"),
      "USXGMII get_state reads cached state without regmap_lock")
check("READ_ONCE(mpcs->poll)" in usx_poll and
      "WRITE_ONCE(mpcs->poll, true)" in usx_enable and
      "WRITE_ONCE(mpcs->poll, false)" in usx_disable and
      usx_disable.find("WRITE_ONCE(mpcs->poll, false)") <
      usx_disable.find("cancel_delayed_work_sync") and
      "mpcs->poll = false" in usx,
      "USXGMII poll flag is not accessed with ordered READ_ONCE/WRITE_ONCE lifecycle")

# Generic PHY API declarations used by the PCS drivers must remain available.
phy_h = read("include/linux/phy/phy.h")
for symbol in ("phy_reset", "phy_power_on", "phy_power_off", "phy_set_mode_ext", "devm_of_phy_get"):
    check(bool(re.search(r"\b" + symbol + r"\s*\(", phy_h)),
          "Linux PHY API declaration missing: " + symbol)

# WED ring cleanup must test the ring being freed, not its peer array.
wed = read("drivers/net/ethernet/mediatek/mtk_wed.c")
free_rx = body(wed, "mtk_wed_free_rx_rings")
check("dev->rx_ring[i].flags" in free_rx and "dev->tx_ring[i].flags" not in free_rx,
      "WED RX ring cleanup checks TX ring flags and can skip configured RX rings")

# WED interrupt-trigger mode must use typed MMIO pointers and check both mappings.
pcie_mask = body(wed, "mtk_wed_set_pcie_mask")
check("void __iomem *apmcu" in pcie_mask and "void __iomem *pcie" in pcie_mask and
      pcie_mask.count("ioremap(") == 2 and "if (!apmcu)" in pcie_mask and
      "if (!pcie)" in pcie_mask and "iounmap(apmcu)" in pcie_mask and
      "iounmap(pcie)" in pcie_mask,
      "WED PCIe interrupt-mask path lacks typed MMIO mappings or complete map/unmap checks")
check("readl(apmcu)" in pcie_mask and "readl(pcie)" in pcie_mask and
      "writel(value, apmcu)" in pcie_mask and "writel(value, pcie)" in pcie_mask and
      "(void *)" not in pcie_mask and "unsigned long addr" not in pcie_mask,
      "WED PCIe interrupt-mask path casts an MMIO pointer through an integer")
check(pcie_mask.find("ioremap(IRQ_MASK_APMCU") < pcie_mask.find("ioremap(dev->hw->pcie_base") <
      pcie_mask.find("writel(value, apmcu)"),
      "WED interrupt mask is modified before both register mappings succeed")
check("mtk_wed_set_pcie_mask(dev, true)" in body(wed, "mtk_wed_start") and
      "mtk_wed_set_pcie_mask(dev, false)" in body(wed, "mtk_wed_stop"),
      "WED PCIe interrupt mask is not paired across start/stop")


# Realtek PHY backports must preserve Linux 6.12 MDIO/PHY/PM API contracts.
eth_phy_h = read("include/linux/phy.h")
hwmon_h = read("include/linux/hwmon.h")
mdio_h = read("include/linux/mdio.h")
wakeirq_h = read("include/linux/pm_wakeirq.h")
device_h = read("include/linux/device.h")
for symbol, header in (
    ("phy_read_mmd_poll_timeout", eth_phy_h),
    ("phy_save_page", eth_phy_h),
    ("phy_restore_page", eth_phy_h),
    ("phy_select_page", eth_phy_h),
    ("devm_hwmon_sanitize_name", hwmon_h),
    ("devm_hwmon_device_register_with_info", hwmon_h),
    ("__mdiobus_c45_read", mdio_h),
    ("dev_pm_set_wake_irq", wakeirq_h),
    ("dev_pm_clear_wake_irq", wakeirq_h),
    ("devm_add_action_or_reset", device_h),
):
    check(bool(re.search(r"\b" + symbol + r"\s*\(", header)),
          "Linux 6.12 Realtek PHY API declaration missing: " + symbol)

realtek_hwmon = read("drivers/net/phy/realtek/realtek_hwmon.c")
hwmon_read = body(realtek_hwmon, "rtl822x_hwmon_read")
hwmon_init = body(realtek_hwmon, "rtl822x_hwmon_init")
check(hwmon_read.count("phy_read_mmd(") == 2 and hwmon_read.count("if (raw < 0)") == 2,
      "RTL822x hwmon treats negative MDIO errors as temperature values")
check("devm_hwmon_sanitize_name" in hwmon_init and
      "devm_hwmon_device_register_with_info" in hwmon_init,
      "RTL822x hwmon uses a registration API not present in Linux 6.12")
check("ret = phy_clear_bits_mmd" in hwmon_init and "if (ret < 0)" in hwmon_init,
      "RTL822x hwmon initialization ignores over-temperature alarm reset failure")

realtek_main = read("drivers/net/phy/realtek/realtek_main.c")
led_set_f = body(realtek_main, "rtl8211f_led_hw_control_set")
led_set_e = body(realtek_main, "rtl8211e_led_hw_control_set")
check("if (index >= RTL8211x_LED_COUNT)" in led_set_f and
      led_set_f.find("if (index >= RTL8211x_LED_COUNT)") < led_set_f.find("mask = RTL8211F_LEDCR_MASK"),
      "RTL8211F LED index is shifted before its bounds check")
check("if (index >= RTL8211x_LED_COUNT)" in led_set_e and
      led_set_e.find("if (index >= RTL8211x_LED_COUNT)") < led_set_e.find("cr1mask = RTL8211E_LEDCR1_MASK") and
      led_set_e.find("if (index >= RTL8211x_LED_COUNT)") < led_set_e.find("cr2mask = RTL8211E_LEDCR2_MASK"),
      "RTL8211E LED index is shifted before its bounds check")


wol_get = body(realtek_main, "rtl8211f_get_wol")
wol_set = body(realtek_main, "rtl8211f_set_wol")
check("wol->wolopts = 0" in wol_get and "wol_events < 0" in wol_get,
      "RTL8211F get_wol does not clear stale state and handle MDIO read failure")
check("phy_save_page" in wol_set and "phy_restore_page" in wol_set and
      "ret < 0" in wol_set,
      "RTL8211F set_wol does not preserve page state and propagate MDIO failures")

rtl_probe = body(realtek_main, "rtl8211f_probe")
clear_wake = body(realtek_main, "rtl8211f_clear_wake_irq")
check("dev_pm_clear_wake_irq" in clear_wake and
      "ret = dev_pm_set_wake_irq(dev, phydev->irq)" in rtl_probe and
      "devm_add_action_or_reset(dev, rtl8211f_clear_wake_irq, dev)" in rtl_probe and
      "devm_pm_set_wake_irq" not in realtek_main and
      rtl_probe.find("if (ret)") < rtl_probe.find("device_set_wakeup_capable(dev, true)"),
      "RTL8211F probe does not use the Linux 6.12 wake-IRQ API with managed cleanup")

if failures:
    for failure in failures:
        print("FAIL: " + failure, file=sys.stderr)
    raise SystemExit(1)
print("PASS: Linux phylink/PHY APIs, Realtek MDIO/WoL/hwmon/LED, PCS lifecycle and WED resource contracts")

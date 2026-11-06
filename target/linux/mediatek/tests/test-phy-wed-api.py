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

# Linux phylink callback contract introduced by the 6.14 backport series.
phylink_h = read("include/linux/phylink.h")
phylink_c = read("drivers/net/phy/phylink.c")
check(bool(re.search(
    r"pcs_get_state\s*\)\s*\(\s*struct phylink_pcs\s*\*\s*pcs\s*,\s*"
    r"unsigned int\s+neg_mode\s*,\s*struct phylink_link_state\s*\*\s*state",
    phylink_h, re.S)),
    "phylink_pcs_ops pcs_get_state callback does not expose the Linux 6.14 neg_mode parameter")
check(bool(re.search(
    r"phylink_mii_c22_pcs_decode_state\s*\(\s*struct phylink_link_state\s*\*\s*state\s*,\s*"
    r"unsigned int\s+neg_mode", phylink_c, re.S)),
    "phylink_mii_c22_pcs_decode_state signature is incompatible with the backported callers")

# SGMII PCS: regmap errors must release the mutex and publish link-down state.
lynxi = read("drivers/net/pcs/pcs-mtk-lynxi.c")
lynxi_status = body(lynxi, "mtk_pcs_lynxi_link_status")
lynxi_update = body(lynxi, "mtk_pcs_lynxi_update_state")
lynxi_poll = body(lynxi, "mtk_pcs_lynxi_link_poll")
lynxi_enable = body(lynxi, "mtk_pcs_lynxi_enable")
lynxi_disable = body(lynxi, "mtk_pcs_lynxi_disable")
check("if (regmap_read" in lynxi_status and "val = 0" in lynxi_status and
      "mutex_unlock(&mpcs->regmap_lock)" in lynxi_status,
      "SGMII link-status read does not map regmap failure to link-down")
check("state.link = false" in lynxi_update and "state->link = false" not in lynxi_update and
      "mutex_unlock(&mpcs->regmap_lock)" in lynxi_update and
      "mtk_pcs_lynxi_store_mpcs_state(mpcs, &state)" in lynxi_update,
      "SGMII update-state error path has a pointer/member error or leaks regmap_lock")
check("mpcs->poll && !delayed_work_pending(&mpcs->link_poll)" in lynxi_poll,
      "SGMII poll worker can requeue after polling has been disabled")
check("mpcs->poll = true" in lynxi_enable and "schedule_delayed_work" in lynxi_enable,
      "SGMII PCS enable does not activate delayed polling")
check("mpcs->poll = false" in lynxi_disable and
      lynxi_disable.find("mpcs->poll = false") < lynxi_disable.find("cancel_delayed_work_sync"),
      "SGMII PCS disable does not stop requeueing before cancelling work")
check("mpcs->poll = false" in lynxi,
      "SGMII PCS polling is not initialized disabled")

# USXGMII PCS uses the same enable/disable contract.
usx = read("drivers/net/pcs/pcs-mtk-usxgmii.c")
usx_poll = body(usx, "mtk_usxgmii_pcs_link_poll")
usx_enable = body(usx, "mtk_usxgmii_pcs_enable")
usx_disable = body(usx, "mtk_usxgmii_pcs_disable")
check("mpcs->poll && !delayed_work_pending(&mpcs->link_poll)" in usx_poll,
      "USXGMII poll worker can requeue after polling has been disabled")
check("mpcs->poll = true" in usx_enable and "schedule_delayed_work" in usx_enable,
      "USXGMII PCS enable does not activate delayed polling")
check("mpcs->poll = false" in usx_disable and
      usx_disable.find("mpcs->poll = false") < usx_disable.find("cancel_delayed_work_sync"),
      "USXGMII PCS disable does not stop requeueing before cancelling work")
check("mpcs->poll = false" in usx,
      "USXGMII PCS polling is not initialized disabled")

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
check("void __iomem *addr" in pcie_mask and pcie_mask.count("ioremap(") == 2 and
      pcie_mask.count("if (!addr)") == 2 and pcie_mask.count("iounmap(addr)") == 2,
      "WED PCIe interrupt-mask path lacks typed MMIO mapping or complete map/unmap checks")
check("readl(addr)" in pcie_mask and "writel(value, addr)" in pcie_mask and
      "(void *)addr" not in pcie_mask and "unsigned long addr" not in pcie_mask,
      "WED PCIe interrupt-mask path casts an MMIO pointer through an integer")
check("mtk_wed_set_pcie_mask(dev, true)" in body(wed, "mtk_wed_start") and
      "mtk_wed_set_pcie_mask(dev, false)" in body(wed, "mtk_wed_stop"),
      "WED PCIe interrupt mask is not paired across start/stop")


# Realtek PHY backports must preserve Linux 6.12 MDIO/PHY/PM API contracts.
eth_phy_h = read("include/linux/phy.h")
mdio_h = read("include/linux/mdio.h")
wakeirq_h = read("include/linux/pm_wakeirq.h")
device_h = read("include/linux/device.h")
for symbol, header in (
    ("phy_read_mmd_poll_timeout", eth_phy_h),
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
print("PASS: Linux phylink/PHY APIs, PCS poll lifecycle and WED resource contracts")

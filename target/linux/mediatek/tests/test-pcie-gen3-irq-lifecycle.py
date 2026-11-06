#!/usr/bin/env python3
"""Static contract checks for the patched MediaTek PCIe Gen3 IRQ lifecycle."""
from pathlib import Path
import sys

def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)

def body(source, signature):
    start = source.rfind(signature)
    if start < 0:
        fail(f"missing function: {signature}")
    brace = source.find("{", start)
    if brace < 0:
        fail(f"missing function body: {signature}")
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:i]
    fail(f"unterminated function: {signature}")

def require(condition, message):
    if not condition:
        fail(message)

if len(sys.argv) != 2:
    fail("usage: test-pcie-gen3-irq-lifecycle.py <kernel-source>")
root = Path(sys.argv[1])
path = root / "drivers/pci/controller/pcie-mediatek-gen3.c"
if not path.is_file():
    fail(f"missing patched source: {path}")
src = path.read_text(errors="replace")

parse = body(src, "static int mtk_pcie_parse_msi(")
require("platform_irq_count(pdev)" in parse and "pcie->num_irqs <= 0" in parse,
        "MSI parser must reject zero/negative platform IRQ counts")
require("devm_kcalloc" in parse and "pcie->irqs[i].irq = -1" in parse,
        "MSI IRQ array must be overflow-safe and initialize invalid IRQ sentinels")
require("count % 2" in parse and "count / 2 != pcie->num_irqs" in parse,
        "msi-map must contain exactly two cells per platform IRQ")
require("!msimap[i * 2 + 1]" in parse and "PCIE_MSI_GROUP_NUM" in parse,
        "msi-map group and mask values must be range/bounds checked")
require("else\n\t\t\treturn -EINVAL;" in parse,
        "unknown msi_type values must be rejected")

setup = body(src, "static int mtk_pcie_setup_irq(")
require("goto err_irq;" in setup and "mtk_pcie_irq_teardown(pcie);" in setup,
        "partial chained-IRQ registration must roll back on failure")
require("pcie->irqs[i].irq = pcie->irq" in setup and "platform_get_irq(pdev, i)" in setup,
        "setup must map every declared IRQ and reuse the first acquired IRQ")

teardown = body(src, "static void mtk_pcie_irq_teardown(")
require("pcie->irqs[i].irq < 0" in teardown and "irq_dispose_mapping" in teardown,
        "teardown must skip uninitialized IRQ entries and dispose acquired mappings")
require("pcie->intx_domain = NULL" in teardown and "pcie->msi_domain = NULL" in teardown
        and "pcie->msi_bottom_domain = NULL" in teardown,
        "teardown must clear removed IRQ-domain pointers")

affinity = body(src, "static int mtk_pcie_intx_set_affinity(")
require("if (!port_data)" in affinity and "if (ret >= 0)" in affinity,
        "INTx affinity callback must validate parent IRQ data and propagate failure")

read = body(src, "static int mtk_pcie_config_read(")
write = body(src, "static int mtk_pcie_config_write(")
require("READ_ONCE(pcie->soft_off)" in read and "*val = ~0U" in read
        and "PCIBIOS_DEVICE_NOT_FOUND" in read,
        "config reads during soft-off must report a missing device and all-ones data")
require("READ_ONCE(pcie->soft_off)" in write and "PCIBIOS_DEVICE_NOT_FOUND" in write,
        "config writes during soft-off must not report success")

soft_off = body(src, "int mtk_pcie_soft_off(struct pci_bus *bus)")
soft_on = body(src, "int mtk_pcie_soft_on(struct pci_bus *bus)")
require("mutex_lock(&pcie->power_lock)" in soft_off and "WRITE_ONCE(pcie->soft_off, true)" in soft_off,
        "soft-off state transition must be serialized")
require("pci_dev_put(dev)" in soft_off and "out_put_dev:" in soft_off,
        "soft-off must release device references on all error paths")
require("mutex_lock(&pcie->power_lock)" in soft_on and "WRITE_ONCE(pcie->soft_off, false)" in soft_on,
        "soft-on state transition must be serialized")
require(soft_on.count("pci_dev_put(dev)") >= 2 and "mtk_pcie_power_down(pcie);" in soft_on,
        "soft-on must release device references and power down after startup failure")
require("struct mutex power_lock;" in src and "mutex_init(&pcie->power_lock);" in body(src, "static int mtk_pcie_setup("),
        "power mutex must be declared and initialized before the exported API is used")

print("PASS: PCIe Gen3 MSI bounds, IRQ rollback, affinity and soft-power lifecycle contracts")

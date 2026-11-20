# Pre-cleanup branch archive index

Created: 2026-11-12
Repository: laodadelaoda/immortalwrt-mt798x-rebase
Maintenance branch: n60pro-mtk-closed-driver

This index preserves the five pre-cleanup branch tips as separate archive refs.
The refs preserve the complete Git trees and commit ancestry at the recorded SHAs.
They are archival snapshots, not approval to merge their contents into the maintenance branch.

| Original branch | Archive ref | Preserved tip |
|---|---|---|
| audit/merge-011-013-20261109 | archive/pre-cleanup-2026-11-12/merge-011-013 | f8964b00081a5fa2a7e3e7177b021a7ea4edb91c |
| audit/openssl-3.5.9-inventory-and-prepare-fixes | archive/pre-cleanup-2026-11-12/openssl-inventory-prepare | 4990c66edc09ff685cbbf3df474401636d2b7676 |
| audit/openssl-target-preprocessor-failclosed | archive/pre-cleanup-2026-11-12/openssl-preprocessor | be686e7081a98abef1f6efcb558e8098cd4a9d1d |
| n60-kernel-audit-rework | archive/pre-cleanup-2026-11-12/kernel-audit | 3b707a0ffa474186ac9f2ad0877ead0661623035 |
| wip/openssl-dh-026-staging | archive/pre-cleanup-2026-11-12/openssl-dh-staging | 389189bc4a7189940bb831ed893afb759d72c21f |

## Unique assets and disposition

### audit/merge-011-013-20261109
- Snapshot includes changes to N60 Pro DTS, LED setup, image sizing, HNAT package metadata, and SMP/RPS handling.
- Disposition: archive only. Do not migrate DTS, LED, flash/image, or board behavior changes without separate hardware/configuration evidence. Review HNAT/SMP changes independently if relevant.

### audit/openssl-3.5.9-inventory-and-prepare-fixes
- Unique candidate assets include package/mtk/applications/easymesh-n60/patches/024-dpp-secret-buffer-lifecycle.patch, tests/test-dpp-credential-lifecycle.py, OpenSSL API inventory tests, Provider runtime test changes, and EasyMesh maintenance-group CSV updates.
- Disposition: archive only pending source-level review, exact patch replay, API semantic/lifecycle validation, and inclusion decision against the current 40-item migration scope. Presence in this archive is not a migration pass.

### audit/openssl-target-preprocessor-failclosed
- Contains the OpenSSL target-preprocessor audit script/test revisions and openssl-target-preprocessor-regression.yml.
- Disposition: compare against maintenance-branch versions; retain only demonstrably missing, validated behavior. Same-path files with different blob SHAs are not assumed equivalent.

### n60-kernel-audit-rework
- Candidate assets include target/linux/mediatek/tests/KERNEL-6.12-PATCH-AUDIT.md, audit-kernel-source-structure.py, DSA/Netlink tests, network-offload tests, wrapper tests, and Linux 6.12 patch-stack revisions.
- Disposition: archive only pending clean-source replay, zero-fuzz/zero-offset verification, dependency/order audit, and source/config-bound credentials. No Full build authorization is implied.

### wip/openssl-dh-026-staging
- The compared branch delta is concentrated in package/mtk/applications/mtk-smp/files/smp.sh and target/linux/mediatek/filogic/base-files/etc/hotplug.d/net/30-ext-devices-rps-setting; it does not establish a validated DH/026 migration.
- Disposition: archive only; do not treat its branch name as evidence of DH work.

## Cleanup safety
- Verify each archive ref exists and resolves to the recorded SHA before deleting the corresponding original branch.
- Do not delete archive refs as part of the five-branch cleanup.
- Do not merge archived trees wholesale.
- Keep the maintenance branch as the sole active development branch; archive refs are immutable recovery points.
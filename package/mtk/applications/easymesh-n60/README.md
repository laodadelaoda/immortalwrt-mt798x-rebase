# N60 Pro vendor-source and compatibility audit

## Scope and source of truth

The N60 Pro vendor source set is pinned by package/mtk/vendor-sources.lock.json. The lock binds archive names and SHA256 values, package ownership, extraction roots, patch directories, patch order, and audit-only source sets.

The locked inventory contains 11 source archives and 91 ordered vendor patches across seven patch sets. n60-vendor-source-transforms.py is the single shared source-normalization/transform entry used by both native package Build/Prepare and the audit path; Quick and Full must consume the same lock and attestation.

## Source ownership

| Source set | Owning package / Makefile | Patch set | Scope |
|---|---|---:|---|
| WAPP, MAPD, 1905daemon, libmapd | package/mtk/applications/easymesh-n60/Makefile | 12 | Built EasyMesh components |
| datconf | package/mtk/applications/datconf/Makefile | 1 | Separate package; patches stay with datconf |
| mt_wifi | package/mtk/drivers/mt_wifi/Makefile | 44 | Vendor Wi-Fi driver |
| conninfra | package/mtk/drivers/conninfra/Makefile | 17 | Connectivity infrastructure driver |
| warp | package/mtk/drivers/warp/Makefile | 12 | WARP driver |
| mapfilter | package/kernel/mapfilter/Makefile | 2 | Kernel netfilter package |
| bndstrg_plus, fwdd | Audit inventory only | 2 auxiliary | Not built or installed by the N60 EasyMesh package |

Patches belong to the package that owns the modified source. Linux in-tree APIs and drivers belong in target/linux/mediatek/patches-6.12/; separately packaged drivers and user-space components retain their package-local patch directories. Do not move unrelated WAPP/MAPD/P1905, conninfra, WARP, or datconf changes into EasyMesh merely because they are part of the same firmware.

## Keep patch classes separate

Review and document each change as one of these classes:

1. Vendor functional patch — preserves the vendor feature and its intended semantics.
2. Vendor functional evolution — a later vendor behavior change; do not mislabel it as a Linux 6.12 port.
3. Kernel/API compatibility delta — only the source-ownership package or kernel patch stack that actually needs the API adaptation.
4. Independent correctness/security fix — bounds, NULL handling, ownership, cleanup, secret redaction.
5. Build integration / portability — recursive toolchain flags, headers, libc portability, generated metadata.
6. N60 profile configuration — product-specific radio/MBO behavior; not a kernel API compatibility patch.

The shared transform script includes both source/build portability adjustments (structure layout, bounded path copies, toolchain flag propagation, inet_make_mask declaration and libc portability) and N60 profile choices (MBO/interworking values and the two-interface ra0/rax0 configuration). Keep those classes explicit in review records; do not describe profile behavior as a Linux 6.12 migration.

## WTS and MAC policy

- Keep the vendor WTS template, field order, and vendor parser/read path.
- Do not add a WTS generator or a replacement parser.
- WTS security changes remain ordinary .patch files, including patches/011-wapp-wts-security.patch and patches/012-p1905-wts-hardening.patch.
- Bound both input bytes and parsed record count before any indexed BSS write; fail closed and clear partially populated output on malformed input.
- The P1905 parser rejects excess rows and malformed mandatory fields, and stages MAP-R2 policy changes until parsing and file close succeed.
- Redact PSK/private-key material from logs.
- Obtain AL MAC and BSS MAC dynamically from the live interface/driver; do not hardcode device MAC addresses.
- N60 must not enable CONFIG_MTK_6G_SUPPORT, CONFIG_MTK_MAP_R2_6E_SUPPORT, or CONFIG_MTK_MAP_R3_6E_SUPPORT; WTS/radio configuration remains 2.4/5 GHz only.

## OpenSSL 3 and DPP

The source audit checks for direct EVP_PKEY opaque-structure access, native public accessors, DPP parameter bounds, hex-length parity, allocation NULL checks, per-interface allocation rollback, and credential-log redaction. Deprecated OpenSSL APIs still present in vendor code are not automatically proof of incompatibility; compile/link against the target OpenSSL 3 headers and libraries is still required before claiming full compatibility.

The wapp_dpp_save_dpp_cred() ownership path for temporary authentication buffers must be reviewed alongside its caller error paths. A static regex check of allocation sites alone is not a substitute for proving whether those buffers are copied, transferred, or freed on every failure path.

## Opaque MAPD objects and legacy reference ELF files

Seven pinned AArch64 MAPD object files and four static archives have no corresponding source. They are opaque inputs: source-level Linux/OpenSSL review cannot establish their internal compatibility. Their hashes and ELF metadata are inventoried; target link and symbol-resolution checks remain mandatory.

Eight legacy ELF files are retained as audit references. They include OpenSSL 1.1 dependencies, but the package install path must install source-built outputs rather than those reference binaries or legacy OpenSSL 1.1 libraries. Verify the final package payload before release.

## Verification boundary

The vendor audit verifies archive SHA256 values, complete extracted-source inventories, locked patch order, zero-fuzz patch application, shared transforms, package dependency edges, WTS/DPP static contracts, MAC policy, radio profile, and startup ordering. Native Build/Prepare is not a compile or link test. Do not claim complete Linux 6.12.112 / OpenSSL 3 compatibility until the full Quick compile/link and required Full integration checks pass using the same immutable lock and attestation.

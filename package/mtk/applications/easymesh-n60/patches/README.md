# EasyMesh N60 patch series

This directory is a flat patch store because the package's native `Build/Prepare`
resolves patch paths from the canonical vendor Lock. Do not sort or apply these
files with a shell glob: **the Lock is the only ordering authority**.

## Application phases

1. **Application patches** — applied to the four extracted vendor source trees
   in the exact `patch_sets[easymesh].application_order` sequence.
2. **Normalize** — performed once after the application phase by
   `n60-vendor-source-transforms.py normalize`.
3. **Post-normalize patches** — applied in the exact
   `post_normalize_order` sequence. The Lock's
   `post_normalize_root_suffixes` determines each patch root; notably the
   P1905 path-specific patches must not be applied at the package root by
   guesswork.

The package Makefile uses `patch --batch --forward --fuzz=0`. Keep this
fail-closed behavior. Any patch rename, split, merge, or relocation must be
reflected atomically in the Lock and its audit/workflow consumers.

## File ownership and patch families

| Family | Files / purpose | Ordering note |
|---|---|---|
| WAPP main source / DPP parser and lifecycle | `002-wapp-main-source-safety.patch`, `002-map-1905-config-safety.patch`, `002-wapp-dpp-source.patch`, `010-wapp-wdev-source.patch`, `015-dpp-config-lookup-null-and-error-guard.patch` | Each patch owns one source file; the DPP source patch consolidates OpenSSL 3 provider migration and empty-private-key bootstrap handling. Retain the exact Lock order. |
| OpenSSL 3.5.9 | `007-wapp-dpp-header.patch`, `024-openssl-3.5.9-evp-aes-wrap-and-des-internal.patch`, `024-1905daemon-crypto-openssl-source.patch`, `024-wapp-crypto-header.patch`, `027-1905daemon-dpp-source.patch`, `027-wapp-dpp-reconfig-source.patch`, `032-*`, `034-*` | Names identify the modified source file; keep WAPP and 1905daemon ownership separate. |
| WAPP WTS / event / ABI | `011-wapp-dpp-ctrl-source.patch`, `011-1905daemon-file-io-source.patch`, `011-1905daemon-multi-ap-source.patch`, `011-mapd-topology-srv-source.patch`, `012-*`, `020-wapp-off-ch-scan-header.patch`, `021-*`, `022-*`, `037-wapp-ieee80211v-defs-header.patch`, `037-wapp-map-header.patch`, `037-wapp-map-source.patch`, `045-mapd-wapp-if-header.patch`, `045-mapd-wapp-if-source.patch` | WTS parser changes in 1905 `file_io.c` are order-dependent; retain the Lock sequence. |
| P1905 / libbridge | `001-dsa-*`, `002-p1905-libbridge-path-max-conflict.patch`, `002-p1905-libbridge-devif-source.patch`, `006-p1905-libbridge-tool-propagation.patch`, `006-1905daemon-ethernet-makefile.patch`, `039-*`, `040-*`, `041-*`, `043-*` | Each Makefile/source owner has its own patch; both 006 patches carry recursive toolchain variables and remain in Lock order. |
| MAPD | `044-mapd-main-source.patch`, `046-*`, `047-mapd-ch-planning-r2-source.patch`, `047-mapd-ch-planning-source.patch`, `049-mapd-client-db-header.patch`, `049-mapd-topology-srv-header.patch`, `051-mapd-ap-est-unlink-query-buffer-size.patch` | 044 consolidates all MAPD main-source changes in mapd.c, including the unused-local and cent_str_en fixes plus ABI assertions and callers; 047's header/source fixes remain separate by file. 049 client DB and topology header patches each consolidate all changes to their respective header, including the explicit MLD typedef, ABI storage layout, and N60 non-6-GHz declaration guards. 051 sizes the AP estimator's variable-length unlink query buffer from the packed structure plus one STA MAC, without enabling 6 GHz. |
| libmapd | `004-libmapd-target-flags.patch` | Independent Makefile-only change. |

The `002-wapp-main-source-safety.patch` also corrects WAPP CLI path-copy bounds:
`-f` uses the 256-byte AP-config buffer, while `-F` and `-u` use their
128-byte MAP-config buffers. It removes the pointer-size `sizeof()` mistake
that truncated paths on 64-bit targets and explicitly NUL-terminates each copy.

## Maintenance rules

- Keep each patch focused on one source file wherever practical. A patch may
  contain multiple hunks for that same file.
- Within a patch, keep hunks in ascending source order: both old-file and
  new-file start positions must be monotonic. If repeated sections represent
  sequential edits to overlapping ranges, do not sort their headers blindly;
  replay the complete Lock prefix from pristine source, then regenerate one
  unified diff from the exact pre-patch and post-patch files.
- When splitting or merging, derive the result from the pristine locked archive
  plus the complete preceding Lock sequence—not from a partially patched tree.
- Preserve source semantics and ABI, especially closed MAPD library symbols,
  DPP credential ownership, WTS parser rollback, and N60's non-6-GHz behavior.
- After any content or ordering change, replay every affected phase from clean
  archives with zero fuzz, zero offset, zero rejects, and compare the final
  source tree. Update the Lock and audit credentials in the same change.
- Patch filenames must identify their actual modified source file. Do not use
  numeric appendage suffixes to distinguish revisions. If several patches
  touch the same source file, consolidate them into one canonical file-scoped
  patch when dependency order and pristine-source replay permit it; otherwise
  document the concrete ordering dependency and keep the names source-specific.


# N60 Pro Full build authorization

This commit authorizes one Full firmware pipeline on `n60pro-25.12-upstream-base`, but only if the fresh canonical Vendor Audit job for this exact commit succeeds.

## Evidence prerequisite

- Previous complete vendor replay and native Prepare: [run #45104536870](https://github.com/laodadelaoda/immortalwrt-mt798x-rebase/actions/runs/45104536870)
- Audited source/patch commit: `63d6bcd13bbe2fa65e1053792d6fa9f431785c32`
- Vendor lock SHA256: `6d6e49fb766feb951eee97ed686f3567ed55c68505fbd1cd4635362f4a52abb2`
- 146 active fixed-vendor/EasyMesh patch files; zero patch failures, fuzz, offset or reject
- MT Wi-Fi 026 exact Prepare assertions passed
- MT Wi-Fi patch 114: 11/11 hunks, zero fuzz/offset
- Native OpenWrt Prepare passed for MT Wi-Fi, Conninfra, WARP, MAPFILTER, datconf and EasyMesh

## Execution constraints

- Do not run Quick.
- Do not exclude or skip any existing patch.
- The Full job must wait for the fresh Vendor Audit on this commit.
- The build must use the same branch, lock-managed vendor sources and complete N60 Pro configuration.
- Preserve all audit artifacts, source hashes, firmware hashes and build logs.
- A successful compile is not hardware acceptance; N60 Pro boot, MTK Wi-Fi and EasyMesh interoperability remain mandatory.

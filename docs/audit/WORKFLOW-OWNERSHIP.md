# N60 Pro workflow ownership

Status: consolidated to two operational workflows
Target branch: `n60pro-25.12-upstream-base`
Platform: Netcore N60 Pro / MediaTek MT7986AV
Baseline: ImmortalWrt 25.12 / Linux 6.12.116 / OpenSSL 3.5.9

## The two retained workflows

| Workflow | Responsibility |
|---|---|
| `.github/workflows/upstream-sync-n60pro.yml` | Track ImmortalWrt `openwrt-25.12`, compare upstream and N60 Pro history and changed paths, map equivalent/partial/unmapped commits, prepare or update one stable candidate branch and PR, then dispatch Full Build for that exact candidate revision. |
| `.github/workflows/n60pro-build.yml` | The only build entry point. Build complete N60 Pro firmware using the repository's source, configuration, patches and toolchain; verify firmware output; upload the firmware artifact. For a dispatched upstream candidate, merge its PR only after the exact candidate SHA passes Full compilation and non-empty firmware artifact validation. |

## Consolidation boundary

EasyMesh adaptation, vendor patch replay, Quick build, separate upstream auto-merge, and branch-cleanup workflows are no longer independent workflow owners. Their obsolete workflow files and the Quick composite action are removed. Valid source patches, package definitions, vendor archives and locks, N60 Pro configuration, and native OpenWrt build behavior remain in the source tree and are consumed by Full Build.

## Upgrade and build safety

- The maintained target branch is `n60pro-25.12-upstream-base`; upstream synchronization uses one stable candidate ref rather than per-run branches.
- Upstream commit mapping and path inventories are review aids. Patch IDs are not semantic equivalence; unmapped, split/squash, ambiguous and merge commits require path/function-level handling.
- Candidate publication is followed by the same Full Build used for ordinary N60 Pro firmware.
- Candidate merge requires an exact match between the PR head SHA and the Full Build SHA, successful full compilation, and a verified non-empty firmware artifact.
- Full Build has no dependency on a separate EasyMesh/Vendor Audit workflow or stale run-bound audit artifacts.
- Workflow consolidation does not delete valid EasyMesh, MTK closed-driver, Linux kernel, WARP, Conninfra, MAPFILTER, datconf, OpenSSL, or device configuration source.
- A successful Action without a verified firmware output is not accepted as a completed build.

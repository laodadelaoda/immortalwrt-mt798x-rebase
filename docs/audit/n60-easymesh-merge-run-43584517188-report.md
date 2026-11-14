# N60 Pro EasyMesh 033-037 consolidation candidate

- Repository input commit: ca466d519b28ed294594e49bfbc3d5b394c2e01d
- Core patch input baseline (002/007/008/010/015/016): 4289d029c18ccebf8525af80f5f656f62f9dc1a2
- Standalone legacy patch input baseline (033-037): 4be17091600a8da8641c1579bf4d0963cb60d655
- WAPP archive: wappd-80ca5724.tar.bz2
- WAPP archive SHA256: 73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462
- Original Lock-order reference replay with the 033 overlap merged into 010 and 037 hunk counts corrected: PASS (zero fuzz/reject; historical offsets are rebased into the generated patches).
- Consolidated-order replay: PASS
- Generated unified-diff replay: PASS
- Final source tree byte parity: PASS
- 033 overlap: its exact two-line PSK clear was moved into the existing 010 config-memcpy ownership hunk; no other 033 hunk was dropped.
- 037 correction: the /dev/null hunk was corrected to -0,0/+1,19 after verifying 19 added lines. The map_1905.c file section was regenerated from the exact pre-037 source with two U3 hunks, removing only the two credential-bearing hexdump calls and retaining functional code and blank separators.

## Responsibility mapping

- 008: original 008 + 035 + 037 (DPP authentication/key lifecycle and diagnostic redaction)
- 010: original 010 + 033 + 036 + the overlapping 016 main.c QR-count hunk (WAPP DPP config-object lifecycle, rollback and destruction)
- 015: original 015 + 034 (DPP configuration lookup, credential retrieval and BSS credential construction)
- 016: dpp.c/dpp.h/dpp_wdev.c remain in 016; its main.c hunk is folded into 010 because 033 requires the post-016 QR-count context.
- 002: unchanged; parser/parameter validation responsibility remains independent

## Generated patch evidence

| Patch | Hunks | Bytes | SHA256 |
|---|---:|---:|---|
| 008-dpp-parser-bounds-and-secret-redaction.patch | 29 | 17512 | ad884aebc4278d312225e3cb3a5afb050ef2e877255c16f8e70627c7b800e3f5 |
| 010-dpp-wdev-config-allocation-rollback.patch | 10 | 20571 | 19147bd2ca08a1f6ae12bf08e9737550f6085b8d7295b4db92b7bfb6307dd5cb |
| 015-dpp-config-lookup-null-and-error-guard.patch | 25 | 29011 | 4bba91423c5efef66fd211e112a2f2dbf20971af85d0cd45b652787a74e5d1d0 |
| 016-dpp-qr-count-boundaries-and-error-propagation.patch | 8 | 15574 | a717fd3bc0a17220e223419cfddbf31aa73538343931332a58505f0ea514b0a1 |

- New Lock SHA256: d910d12d76a436d6253342545f2813431f4ca4d37b9c2fbf49192c5d19b49137
- Removed independent patch files and Lock entries: 033, 034, 035, 036, 037
- No Quick build, Full build, compile or link target invoked.

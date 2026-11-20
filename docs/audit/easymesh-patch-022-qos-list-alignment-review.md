# EasyMesh patch 022 review: QoS intrusive-list container alignment

## Failure evidence

Quick Action #42588905735 passed the fixed-vendor source audit and the no-compile native Package Prepare gate, then failed in the WAPP compile with GCC 14.3.0 and `-Werror=address-of-packed-member`.

The diagnostics identified eight address-taking sites in `wappd/qos/qos.c`:
- MSCS: two list insertion/removal operations plus cleanup;
- SCS: two list insertion/removal operations plus cleanup;
- DSCP policy: list insertion and cleanup.

The affected declarations in `wappd/include/qos.h` were `GNU_PACKED` wrappers whose first member is `struct dl_list`. A `dl_list` contains native pointers. The wrappers are heap-allocated with `os_zalloc`, traversed as intrusive lists, and maintained as internal state; they are not wire-format structures.

## Minimal correction

Patch 022 removes `GNU_PACKED` only from:
- `struct mscs_configuration`;
- `struct scs_configuration`;
- `struct dscp_policy_db`.

The `list` member remains first, preserving offset zero. The patch does not alter list operations, allocation/free ownership, protocol payload structures, DPP/WTS logic, or the fixed vendor archive. This follows the same alignment principle already used by patch 020 for other in-memory WAPP list containers, but covers distinct QoS types in `qos.h`.

## Regression and acceptance gates

- `test-wapp-qos-list-alignment-contract.py` checks the three declarations, first-member position, native list pointer definition, heap-allocation/traversal contract, and absence of raw serialization.
- Patch 022 must replay against the pinned WAPP archive with `--fuzz=0`, no offset and no partial application.
- The fixed-vendor full patch audit must pass with the current Lock and newly generated same-run attestation.
- Quick Prepare must execute the new source contract test.
- WAPP must compile with GCC 14.3.0 and `-Werror`; then the full EasyMesh source build/link and ELF dependency audit must pass.

No compile-warning suppression or change to vendor archive URL/SHA256 is permitted.

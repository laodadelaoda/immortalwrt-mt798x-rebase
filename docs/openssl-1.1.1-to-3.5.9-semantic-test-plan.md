# OpenSSL 1.1.1w → 3.5.9 semantic migration test plan

Status: reference plan only. No vendor API migration is approved by this document.

## Governing rule

For every deprecated API found in WAPP, MAPD, 1905daemon or libmapd:

1. Identify the exact source callsite and its target preprocessor reachability.
2. Read the OpenSSL 3.5 migration-guide section and the exact 3.5 manual page recorded in `openssl-111-to-359-migration-map.csv`.
3. Record the old call's inputs, outputs, error behavior, ownership and cryptographic parameters.
4. Select a replacement only after the old behavior is understood.
5. Run the same test vectors against a pinned OpenSSL 1.1.1w reference build and the pinned 3.5.9 target build.
6. Only then change vendor code and mark the individual map row reviewed. A green compile is not evidence of semantic equivalence.

The migration baseline attestation is a provenance prerequisite. It is not a migration approval.

## Family-by-family differential tests

| Family / APIs | Official 3.5 direction | Required equivalence evidence |
|---|---|---|
| HMAC (`HMAC_CTX_*`, `HMAC_Init_ex`) | `EVP_MAC` HMAC implementation | RFC 4231 vectors; empty and long keys; zero-length and multi-part updates; digest selection; context reinitialization; output length; error propagation |
| CMAC (`CMAC_*`) | `EVP_MAC` CMAC implementation | NIST SP 800-38B vectors for every used AES key size; incremental updates; finalization and reinitialization; exact output length; invalid key/cipher failures |
| AES low-level (`AES_set_*_key`, `AES_wrap_key`, `AES_unwrap_key`) | EVP cipher APIs; AES-WRAP cipher for key wrapping | Preserve mode, key size, IV, padding, in-place/out-of-place behavior and output length; RFC 3394/5649 wrap vectors; tampered wrapped-key rejection; compare ciphertext byte-for-byte |
| DES (`DES_set_key`, `DES_ecb_encrypt`) | EVP cipher APIs; DES is in the Legacy Provider | First prove DES is required by a deployed protocol. If required, test legacy-provider loading explicitly, key parity, weak-key handling and exact ciphertext. Never enable the Legacy Provider globally to silence a failure |
| DH (`DH_*`) | `EVP_PKEY_keygen`, `EVP_PKEY_derive`, `EVP_PKEY_fromdata`, parameter getters | Same group and parameter set; public/private key lengths; peer validation; shared-secret bytes; KDF inputs; invalid peer and invalid parameter rejection; private-key ownership |
| EC group/point (`EC_GROUP_*_GFp`, `EC_POINT_*_GFp`) | Generic `EC_GROUP_get_curve` / `EC_POINT_*` functions without the GFp suffix | Prime-field assumptions; affine coordinates; compressed-point parity; point-at-infinity handling; invalid point rejection; exact encoded point form |
| EC key (`EC_KEY_*`, `EVP_PKEY_*_EC_KEY`) | Provider-backed `EVP_PKEY`, `EVP_PKEY_fromdata`, `OSSL_PARAM` | Named curve; public/private parameter handling; ownership and reference counts; compressed/uncompressed point form; SEC1/PKCS#8 serialization; no unintended private-key export |
| RSA (`RSA_*`) | `EVP_PKEY` and `EVP_PKEY_CTX`; provider for custom method behavior | PKCS#1 v1.5 and PSS signatures; OAEP parameters; digest and salt-length settings; key bits vs encoded size; malformed-key rejection; exact signature verification |
| ENGINE (`ENGINE_*`, `RSA_set_method`) | Provider architecture; no mechanical 1:1 replacement | First prove whether the source is excluded by `OPENSSL_NO_ENGINE` in the actual N60 target preprocessor output. If reachable, document engine controls, key loading, hardware/non-exportable keys, authentication and provider lifecycle before redesign |
| EVP accessors (`EVP_PKEY_cmp`, `EVP_MD_CTX_md`, `EVP_CIPHER_CTX_iv_noconst`) | `EVP_PKEY_eq`, `EVP_MD_CTX_get0_md`, `EVP_CIPHER_CTX_get_updated_iv` | Borrowed vs owned pointer lifetime; equality semantics; current vs original IV; call timing; null/error behavior |
| Encoding (`d2i_ECPrivateKey`, `i2d_ECPrivateKey`, `i2o_ECPublicKey`) | `OSSL_DECODER`, `OSSL_ENCODER`, `EVP_PKEY_get1_encoded_public_key` | Preserve SEC1 vs PKCS#8, DER vs PEM, point conversion form, password callback, output bytes/length, parse compatibility and error queue |
| SHA-1 (`SHA1_Transform`) | EVP digest API for complete-message hashing; no assumed raw-transform equivalent | Inspect whether the caller supplies a complete message or manipulates raw compression state. If raw state/padding semantics are required, redesign; do not substitute a one-shot digest call |

## Initial source-review priority

The original source inventory (Run 42724660705) reported 429 deprecated-name occurrences. Five were references inside unexpanded WAPP macro definitions, leaving 424 source-level callsite occurrences across 63 API names after the macro-reachability correction. These are lexical source occurrences, not yet a count of target-preprocessed active calls.

| Review cluster | Source-level occurrences after macro correction | Priority rationale |
|---|---:|---|
| EC / EVP_PKEY legacy bridge | 282 | Dominant ownership and provider-compatibility risk; review the whole EC key lifecycle together |
| DH / DSA / RSA | 51 | Key object ownership, key generation/derivation, padding and serialization |
| HMAC / CMAC | 40 | Digest/cipher parameters, incremental operation and output equivalence |
| ENGINE / provider redesign | 20 | First resolve `OPENSSL_NO_ENGINE` reachability; if active, redesign rather than rename |
| Key encoding / decoding | 13 | Preserve SEC1/PKCS#8, DER/PEM and EC point form |
| AES / DES cipher | 12 | Preserve modes, IV/padding and legacy-provider constraints |
| EVP generic / other | 4 | Accessor semantics, return codes and object lifetime |
| SHA-1 low-level | 2 | Determine whether raw compression state is being manipulated |

The 20 ENGINE occurrences are not yet confirmed as compiled calls; the N60 OpenSSL package selects `no-engine`, but the target preprocessor guard stack must prove exclusion. Counts must be refreshed from the current Quick Prepare artifact before any migration patch is proposed.

## WAPP source-specific findings (preliminary, fixed archive)

The source archive used for this review is WAPP `wappd-80ca5724.tar.bz2`, SHA256 `73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462`, matching the current vendor source lock. The inspected DPP artifact is a preliminary 017→018 patch-stage snapshot; the final callsite inventory must be refreshed from the current complete native Prepare tree before approving any patch.

### EC / EVP_PKEY bridge is not a mechanical accessor replacement

The WAPP DPP implementation uses the legacy EC_KEY bridge for protocol arithmetic, not merely to read a curve name:

- `dpp_auth_derive_l_responder`: computes `L = ((bR + pR) mod q) * BI`. It reads two local private scalars, the peer bootstrap public point and group order, then performs scalar arithmetic and point multiplication.
- `dpp_auth_derive_l_initiator`: computes `L = bI * (BR + PR)`. It adds two peer public points and multiplies by a local private scalar.
- DPP reconfiguration derives `M = cI * (CR + PR)` and `M = ((cR + pR) mod q) * CI`, again requiring point addition and private-scalar arithmetic.
- `dpp_gen_reconfig_id`, `dpp_update_reconfig_id` and `dpp_decrypt_e_id` perform random scalar/point generation, point addition, inversion and subtraction. `dpp_decrypt_e_id` explicitly computes `E-id = E'-id - s_C * A-NONCE`.
- `dpp_pkey_from_point` wraps a named-curve public point into an EVP_PKEY; this should be rebuilt with provider-backed `EVP_PKEY_fromdata` and `OSSL_PARAM`, not by creating a legacy EC_KEY.
- `dpp_copy_netaccesskey` serializes an EC private key using `i2d_ECPrivateKey`; the replacement must preserve SEC1 DER, not silently switch to PKCS#8.
- `dpp_process_signed_connector` only needs the curve identity from a public key; a group-name parameter query is sufficient and avoids exporting key material.

OpenSSL 3.5's [EVP_PKEY-EC manual](https://docs.openssl.org/3.5/man7/EVP_PKEY-EC/) explicitly documents these provider key parameters: `group` / `OSSL_PKEY_PARAM_GROUP_NAME`, `pub` / `OSSL_PKEY_PARAM_PUB_KEY`, `priv` / `OSSL_PKEY_PARAM_PRIV_KEY`, `encoding` / `OSSL_PKEY_PARAM_EC_ENCODING`, and `point-format` / `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT`. A viable candidate for the low-level arithmetic callsites is to query the group name with `EVP_PKEY_get_utf8_string_param`, public point bytes with `EVP_PKEY_get_octet_string_param`, and—only where protocol arithmetic truly requires it—the private scalar with `EVP_PKEY_get_bn_param`. Reconstruct an owned `EC_GROUP` and `EC_POINT` for the existing non-deprecated generic EC arithmetic. This candidate is **not approved** until actual provider exportability and key ownership behavior are tested. It must not be assumed to work with non-exportable hardware/provider keys.

**Point-format compatibility hazard:** the OpenSSL 3.5 manual states that before 3.0.8 the built-in providers always exported EC points in compressed form, while since 3.0.8 the provider honors `OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT` or defaults to uncompressed. Therefore every migrated import/export path must set the required point format explicitly and compare the exact wire bytes. Relying on the provider default can silently change DPP public-key encodings.

The responder formula involving `bR + pR` is especially important: a simple `EVP_PKEY_derive` substitution is not obviously equivalent because the protocol computes a sum of private scalars before point multiplication. The initiator formula uses a sum of public points; a high-level derive path may be possible after constructing a temporary provider-backed peer key, but the exact x-coordinate and encoding must be compared.

### WAPP ECDH point format

`crypto_ecdh_get_pubkey` returns either the x-coordinate only or x||y depending on `inc_y`. `crypto_ecdh_set_peerkey` reconstructs either a compressed point (with the current y-bit choice) or an affine point, validates that it is on-curve, wraps it as a peer key and derives the shared secret. Tests must preserve the compressed-point parity convention, point validation, coordinate byte lengths and exact derived-secret bytes. Replacing the GFp-suffixed point functions with their generic counterparts is a direct API-family change, but the input/output format is protocol behavior and must not change.

### Distinguish preprocessor reachability from function reachability

In the inspected WAPP snapshot, the only source calls to `crypto_ecdh_get_pubkey` and `crypto_ecdh_set_peerkey` are inside the `#if 0` DPP PFS block. The helper definitions in `crypto/crypto_openssl.c` are outside that block and contain deprecated EC_KEY/GFp API calls. Therefore:

- the PFS caller is preprocessor-disabled;
- the helper definitions may still be compiled into the object;
- no other WAPP source callsites were found in this snapshot, but external consumers and final link composition have not yet been ruled out.

Do not classify these APIs as active runtime paths merely because the helper definitions exist. Conversely, do not delete or ignore them solely because their only in-tree callers are disabled: prove the object/link reachability and package consumers first. The scanner's next improvement should report preprocessor-disabled blocks separately from compiled-but-unreferenced functions.

### WAPP HMAC and CMAC wrapper behavior

The inspected `crypto/crypto_openssl.c` wrappers show that the vector HMAC APIs support MD5, SHA-1, SHA-256, SHA-384 and SHA-512; the separate `crypto_hash_init` interface supports MD5, SHA-1 and SHA-256. The wrappers accept vector/chunked input and have wrapper-specific success/error codes. `crypto_hash_update` currently ignores the low-level update return value, while `crypto_hash_finish` frees the context and returns 0 when either output pointer is NULL; these existing contracts need an explicit caller-impact decision rather than accidental behavior changes. `openssl_hmac_vector` also has a `TEST_FAIL()` fault-injection path. CMAC supports AES-128-CBC and AES-256-CBC, rejects other key lengths, and requires a 16-byte result. The `EVP_MAC` migration must preserve the selected digest/cipher, key length, vector update order, fault-injection path, output length, return semantics and cleanup behavior. A generic HMAC-only test is insufficient.

These WAPP findings explain why the EC and MAC clusters must be reviewed at the callsite/function level. The current vendor code has not been changed based on this preliminary review.

## Mandatory test dimensions

Every API row must identify which dimensions apply. An omitted dimension requires an explicit reason.

- **Cryptographic parameters:** algorithm, digest, cipher, key size, curve/group, padding, IV/nonce, salt length, point conversion form, KDF and encoding format.
- **Output compatibility:** exact bytes where the wire format requires them; otherwise parse/verify equivalence plus length and canonicalization rules.
- **Incremental operation:** zero-length input, one-shot vs chunked updates, repeated init/final, context reuse and in-place buffers.
- **Failure behavior:** invalid lengths, null arguments, malformed keys/points, invalid peer keys, authentication failure, unsupported provider algorithm and allocation failure.
- **Ownership/lifetime:** borrowed vs owned objects, reference-count transitions, transfer-on-set semantics, BIO ownership, cleanup on every error path and no double-free/use-after-free.
- **Error propagation:** return values, OpenSSL error queue, caller-visible failure handling and no success-shaped fallback.
- **Provider behavior:** default vs legacy provider selection, explicit fetch properties, provider availability and non-exportable key handling.
- **Build reachability:** actual target compiler defines, `OPENSSL_NO_ENGINE`, `OPENSSL_NO_MD5`, `OPENSSL_NO_SHA`, `CONFIG_SHA256`, `CONFIG_SHA384`, `CONFIG_SHA512`, `CONFIG_OPENSSL_CMAC`, `CONFIG_FIPS`, conditional compilation and the real Make-expanded include/library paths.

## Differential harness and evidence

The reference and target harnesses must use the exact archive hashes from the migration lock. For each test case, retain:

- test-case ID and API-map row;
- source file/function/callsite and preprocessor guard stack;
- OpenSSL version, archive SHA256, build options and provider configuration;
- input vector hash and expected output/error;
- reference result and target result;
- ownership/lifetime assertions and sanitizer result where applicable;
- reviewer decision, rationale and source patch hash.

The test harness must not silently normalize away differences in key encoding, point format, padding, output length, error behavior or provider selection.

## OpenWrt OpenSSL package overlay gap

The current `package/libs/openssl/patches` directory contains nine patches. Patch `140-allow-prefer-chacha20.patch` changes `include/openssl/ssl.h.in` by conditionally changing the `TLS_DEFAULT_CIPHERSUITES` macro order; it does not change a function prototype, but it does mean the prepared header tree is not byte-identical to the pristine 3.5.9 archive. Other patches modify Configure/build files, provider cipher implementation, openssl.cnf and devcrypto engine sources.

The current baseline attestation binds the OpenSSL package Makefile but does not yet bind the nine patch-file SHA256 values, the actual Make-expanded `PATCH_DIR`, the N60 target config, or the prepared (post-patch) header-tree digest. This is a material reproducibility gap. Close it by recording the actual `PKG_SOURCE`, `PKG_SOURCE_URL`, `PKG_HASH`, `PKG_BUILD_DIR`, `PATCH_DIR` and `OPENSSL_OPTIONS` from GNU Make; hashing every patch in that expanded `PATCH_DIR`; and comparing the prepared header tree against the pristine baseline with the expected patch delta documented. Do not treat the pristine archive header hash alone as proof of the target package's patched header surface.

## N60 ENGINE configuration evidence

The current `config/n60pro-1001.config` does not set `CONFIG_OPENSSL_ENGINE`. The OpenWrt OpenSSL package Makefile therefore selects `no-engine` for this target. This is strong configuration evidence that the ENGINE family should be excluded from the N60 build, but the generated OpenSSL configuration header and target preprocessor output have not yet been captured by the migration audit. Until that proof is attached, the 20 ENGINE-family source occurrences remain unclassified; do not delete or rewrite the guarded code.

## Existing Provider runtime smoke-test coverage and limits

The current Provider runtime test is a useful smoke gate: it exercises SHA-256, AES-GCM encrypt/decrypt, P-256 key generation and ECDSA sign/verify against the 3.5.9 source copy. It does **not** establish 1.1.1w↔3.5.9 equivalence, and it does not cover HMAC/CMAC, DES/Legacy Provider behavior, DH, RSA padding modes, SEC1 serialization, DPP's custom EC point arithmetic, or the target package's exact `OPENSSL_OPTIONS`. Those require the differential family tests above; a passing smoke test must never mark a migration-map row approved.

## Approval states

- `UNREVIEWED`: official guidance found, but source semantics not yet proven.
- `REVIEWED_NOT_APPROVED`: source behavior and proposed replacement documented; differential tests incomplete or failing.
- `APPROVED`: all applicable differential tests pass, ownership/error semantics are reviewed, and a reviewer signs off.
- `RETAINED_WITH_JUSTIFICATION`: legacy API remains only with a specific compatibility reason, scope, test coverage and removal condition.

A policy allow/retain rule may be added only after the corresponding evidence exists. No blanket API-family allowlist is permitted.

## Current gate

The 64-name matrix has official mapping sections and target manual links, but all rows remain `UNREVIEWED` and `approval=false`. The header baseline and run-bound attestation pass. The next work is to inspect the real callsite-context artifact, resolve target preprocessor reachability (especially ENGINE), then create concrete test cases per active API. No WAPP/MAPD/1905daemon source migration or Quick/Full compilation is authorized by this plan.

## Quick Prepare failure review — Run 42731708257

Run URL: https://github.com/laodadelaoda/immortalwrt-mt798x-rebase/actions/runs/42731708257

The fixed-vendor source patch audit completed successfully. The Quick Prepare job reached the strict OpenSSL API migration gate; the inventory self-test passed, then the strict gate returned non-zero because the migration map intentionally has 64 rows with `UNREVIEWED` status. This is an expected fail-closed result, not evidence that the OpenSSL Provider runtime or vendor Prepare failed.

Run-specific audit artifact:
- Artifact ID: `13726904954`
- Name: `n60-openssl-3.5.9-api-and-provider-audit`
- ZIP SHA256: `972c894497599f99380368bfdc0a2b4accd9a533607a8e41aff3d4289f73cb87`

The artifact records 2,833 prepared-source OpenSSL call occurrences, 2,837 pristine-source occurrences, 424 lexical callsites whose names are marked deprecated by OpenSSL 3.5.9 headers, 63 distinct deprecated source API names, 64 migration-map rows and zero const-correctness findings. Three references to `EVP_CIPHER_CTX_iv_noconst` occur only in unreferenced macro definitions; there are no direct deprecated callsites for that API in this run. The 64th map row is therefore a macro-reference/reachability item, not a 64th observed direct call API.

The 424 callsites are lexical source locations, not 424 proven target-preprocessed calls. The artifact explicitly retains this limitation. Several groups require target preprocessing before they can be counted as active migration work:

- Compatibility wrappers guarded by `OPENSSL_VERSION_NUMBER < 0x10100000L` (including local HMAC and DH compatibility shims) are not compiled against OpenSSL 3.5.9. Other HMAC/DH calls outside those wrappers remain independently present and must still be reviewed.
- ENGINE calls are guarded by `OPENSSL_NO_ENGINE` conditions. The OpenWrt package selects `no-engine` for N60, but the exact target preprocessor output is still required before these callsites can be excluded.
- `SHA1_Transform` occurrences are guarded by `OPENSSL_IS_BORINGSSL`; prove that macro is absent in the actual N60 compile environment.
- `CONFIG_NATIVE_WINDOWS`, `CONFIG_SUITEB`, `CONFIG_OPENSSL_CMAC`, `CONFIG_ECC`, `CONFIG_FIPS` and `CONFIG_TESTING_OPTIONS` guarded paths must be resolved against the actual package/component configuration, not inferred from source defaults.

**Required correction to the audit pipeline:** preserve both counts: (1) lexical deprecated references and (2) compiler-preprocessed active references. Add explicit `ACTIVE`, `EXCLUDED_WITH_EVIDENCE` and `UNKNOWN_FAIL_CLOSED` reachability states per callsite. Do not mark a whole API family excluded when only some callsites are guarded. The strict gate must continue to reject any active or unknown deprecated callsite until its migration row and semantic tests are reviewed. Do not change vendor code or approve map rows to clear this run.



## Target-preprocessor reachability audit — implementation status

The current branch was re-inspected after Run 42731708257. The existing inventory implementation still performs lexical scanning of the prepared source tree. Its `callsite_context()` records only opening `#if/#ifdef/#ifndef` lines and pops at `#endif`; it does not model `#else`, `#elif`, continued conditional expressions or macro expansion under the target compiler. Its output is therefore a hint for selecting preprocessor probes, not a reachability result.

The Run 42731708257 artifact was re-counted directly:
- 2,833 lexical OpenSSL call occurrences in prepared sources;
- 424 deprecated-name callsites with context records;
- 223 deprecated-name callsites in `wappd`, 201 in `1905daemon`;
- no deprecated-name callsites were emitted for `mapd` or `libmapd` in this artifact;
- the context parser exposed guard hints including `OPENSSL_VERSION_NUMBER < 0x10100000L` (37 callsites), `OPENSSL_NO_ENGINE` (18), `OPENSSL_IS_BORINGSSL` (2), `CONFIG_NATIVE_WINDOWS` (5), `CONFIG_SUITEB` (7), `CONFIG_OPENSSL_CMAC` (12), `CONFIG_ECC` (36), and `CONFIG_FIPS` (8). These are overlapping, incomplete lexical hints, not mutually exclusive branch counts and not proof of exclusion.

**Reachability disposition:** all 424 deprecated-name callsites are currently `UNKNOWN_FAIL_CLOSED`. None can yet be promoted to `ACTIVE` or `EXCLUDED_WITH_EVIDENCE`, because the artifact contains no per-translation-unit target preprocessor output or exact compile-command manifest. In particular, the 18 ENGINE-guard hints remain unknown. The OpenSSL package Makefile's `no-engine` selection and the absence of `CONFIG_OPENSSL_ENGINE` in the target config are configuration inputs only; neither substitutes for generated target headers plus actual preprocessor output.

The current EasyMesh package Makefile exposes distinct compile environments:
- `libmapd`: `TARGET_CPPFLAGS TARGET_CFLAGS -Werror -g`;
- WAPP: `TARGET_CPPFLAGS TARGET_CFLAGS -Wno-error=deprecated-declarations`, plus the WAPP UAPI include path and package-specific definitions;
- P1905: `EXTRA_CFLAGS` derived from target CPP/C flags, with package-specific DSA/MAP feature definitions and recursive make propagation;
- MAPD: target CPP/C flags through `EXTRA_CFLAGS`, with its own package feature definitions.

Consequently, one generic `-E` invocation or a hand-written set of `-D` flags would be invalid. The next audit implementation must capture the actual GNU Make-expanded compile command for every translation unit in each component, including recursive make variables, generated configuration headers, target sysroot/include ordering and the prepared OpenSSL headers. It must then replay each command as preprocessing only (no object compilation or firmware link), retain source line markers, and bind every result to the target config, toolchain identity, Make-expanded variable snapshot, OpenSSL prepared-header digest, vendor source tree digest and Git SHA.

Required per-callsite state rules:
- `ACTIVE`: the exact deprecated call expression is present in the target compiler's preprocessed translation unit, with source path/line recovered from line markers.
- `EXCLUDED_WITH_EVIDENCE`: the callsite is absent from that translation unit's complete preprocessor output, and the evidence bundle identifies the exact compiler, full arguments, source file, generated headers and preprocessing output hash.
- `UNKNOWN_FAIL_CLOSED`: no exact compile command, missing generated header, preprocessing error, ambiguous source mapping, unsupported compiler wrapper or incomplete evidence. Unknown is a gate failure, never an implicit exclusion.

Do not infer ENGINE exclusion from `no-engine`; do not infer old-version compatibility-wrapper exclusion from a presumed OpenSSL version; do not infer BoringSSL, Windows, SuiteB, FIPS, ECC or CMAC branch reachability from repository defaults. Each callsite must be classified independently from its own translation unit's target preprocessor result. Function-level dead-code/link reachability is a separate later analysis and must not be conflated with preprocessor exclusion.

No supplier source was changed in this audit pass. No firmware or EasyMesh component compilation was performed. The present evidence is insufficient to start API-family migration approval; the strict gate remains closed until the target-preprocessor evidence is generated and independently checked.


## Implemented target-preprocessor audit pipeline (not yet executed on CI)

The implementation is now present on `n60pro-mtk-closed-driver`:

- `scripts/openssl-target-preprocessor-audit.py`
- `tests/test-openssl-target-preprocessor-audit.py`
- `.github/workflows/quick-prepare-audit.yml` — the new audit step is part of the reusable Quick Prepare job and retains its evidence even when a strict gate fails.

This is an implementation commit, **not yet a target-preprocessor pass**. No callsite has been promoted based on the code being present; all classifications remain pending the first complete CI evidence bundle.

### Exact target inputs

The workflow reads expanded variables from the actual EasyMesh package Makefile context using a Make `--eval` target. It captures `TARGET_CC`, `TARGET_AR`, `TARGET_RANLIB`, `TARGET_CPPFLAGS`, `TARGET_CFLAGS`, `TARGET_LDFLAGS`, `STAGING_DIR`, `LINUX_DIR` and `TARGET_PATH`. It does not synthesize compiler flags or `-D` definitions.

It separately reads the OpenSSL package's actual expanded `PKG_SOURCE`, `PKG_SOURCE_URL`, `PKG_HASH`, `PKG_BUILD_DIR`, `PATCH_DIR` and `OPENSSL_OPTIONS`. The artifact records the OpenSSL source identity, package hash, full patch-directory file hashes/tree digest, configured source-tree digest, generated-header digest and the target `.config` digest.

The workflow runs the OpenSSL package Configure step and its `build_generated` header-generation target, then stages the generated public headers. It records `configdata.pm --dump`. The generated `OPENSSL_NO_ENGINE` definition is retained as diagnostic evidence only; it is not itself used to exclude ENGINE callsites.

### No firmware or EasyMesh compilation

The audit does install the N60 cross-toolchain and stage the target development headers for datconf/libkvcutil and libnl-tiny. These are prerequisite toolchain/dependency operations, not a firmware image build and not an EasyMesh component build. OpenSSL Configure/header generation does not compile OpenSSL.

The workflow exports the fully expanded EasyMesh `Build/Compile` recipe as a data artifact using GNU Make's `file()` function; that dump target executes only `true` and does not invoke the package build recipe. The audit validates the expanded recipe's component paths, target compiler, flags, UAPI include path, link flags and recursive Make arguments against the captured target variables. It then invokes each component Makefile directly in `-n -w V=s` mode, avoiding the package-level compound shell recipe (which contains recursive `$(MAKE)` commands and therefore must not be dry-run as a single recipe line). Captured component compiler commands are replayed only as preprocessing (`-E -dD`) and macro snapshot (`-E -dM`). MAPD's `version` metadata target is executed only after its own dry-run is checked and found to contain no compiler invocation.

### Per-translation-unit and per-callsite evidence

The output includes the dry-run logs, extracted compile-command JSON, preprocessed source with line markers, macro snapshot, stderr, SHA256 values and a per-callsite reachability ledger. Each translation unit records the actual target values of:

- `OPENSSL_NO_ENGINE` and `OPENSSL_NO_DEPRECATED_3_0`;
- `OPENSSL_IS_BORINGSSL`;
- `CONFIG_NATIVE_WINDOWS` and `CONFIG_SUITEB`;
- `CONFIG_OPENSSL_CMAC`, `CONFIG_ECC`, `CONFIG_FIPS`, `CONFIG_TESTING_OPTIONS`;
- `OPENSSL_NO_DH` and `OPENSSL_NO_DSA`.

The source conditional-path parser now preserves nested `#if`, continued conditional expressions, `#elif` and `#else` branches. The compiler's preprocessed output, not this lexical branch path, is the deciding evidence.

Direct source occurrences receive one of the three requested states:
- `ACTIVE`: the call expression is present at the mapped source path and line in target-preprocessed output;
- `EXCLUDED_WITH_EVIDENCE`: the component's complete translation-unit set preprocesses successfully and that call expression is absent;
- `UNKNOWN_FAIL_CLOSED`: incomplete Make command enumeration, compiler mismatch, preprocessing failure or ambiguous line mapping.

Macro-body references are emitted in a separate ledger. They are excluded only when the full component preprocessing completes and no active expression for that API exists in the component; otherwise they remain unknown. The audit fails closed on any unknown direct callsite or macro reference.

### ENGINE decision rule

OpenSSL 3.x deprecates ENGINE APIs, but deprecation is not proof that a target build excludes them. The workflow does not convert the textual `no-engine` Configure option into an exclusion decision. For each translation unit, the generated target macro snapshot and actual preprocessor output determine whether `OPENSSL_NO_ENGINE` is defined and whether the guarded ENGINE expression survives. Any missing translation unit or ambiguous mapping leaves the affected callsites unknown.

### First-run acceptance criteria

The first CI evidence bundle must show:
1. all four component Make dry-runs succeeded and every target C/C++ compile command was captured;
2. every captured translation unit completed both preprocessing passes;
3. the compiler identity, target config, Make-expanded OpenSSL source/patch inputs and generated header tree are bound by SHA256;
4. every direct callsite and macro reference has a justified state, with zero `UNKNOWN_FAIL_CLOSED`;
5. ENGINE, old-version compatibility, BoringSSL, Windows, SuiteB, CMAC, ECC and FIPS states are visible in the actual per-translation-unit macro snapshots.

A successful reachability audit still does **not** approve any API migration. Only after it passes will API families be reviewed against the official OpenSSL 1.1.1w/3.5.9 behavior and differential semantic tests. No supplier source has been modified by this implementation.

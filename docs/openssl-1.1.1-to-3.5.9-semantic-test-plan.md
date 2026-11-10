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

## Mandatory test dimensions

Every API row must identify which dimensions apply. An omitted dimension requires an explicit reason.

- **Cryptographic parameters:** algorithm, digest, cipher, key size, curve/group, padding, IV/nonce, salt length, point conversion form, KDF and encoding format.
- **Output compatibility:** exact bytes where the wire format requires them; otherwise parse/verify equivalence plus length and canonicalization rules.
- **Incremental operation:** zero-length input, one-shot vs chunked updates, repeated init/final, context reuse and in-place buffers.
- **Failure behavior:** invalid lengths, null arguments, malformed keys/points, invalid peer keys, authentication failure, unsupported provider algorithm and allocation failure.
- **Ownership/lifetime:** borrowed vs owned objects, reference-count transitions, transfer-on-set semantics, BIO ownership, cleanup on every error path and no double-free/use-after-free.
- **Error propagation:** return values, OpenSSL error queue, caller-visible failure handling and no success-shaped fallback.
- **Provider behavior:** default vs legacy provider selection, explicit fetch properties, provider availability and non-exportable key handling.
- **Build reachability:** actual target compiler defines, `OPENSSL_NO_ENGINE`, conditional compilation and the real Make-expanded include/library paths.

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

## Approval states

- `UNREVIEWED`: official guidance found, but source semantics not yet proven.
- `REVIEWED_NOT_APPROVED`: source behavior and proposed replacement documented; differential tests incomplete or failing.
- `APPROVED`: all applicable differential tests pass, ownership/error semantics are reviewed, and a reviewer signs off.
- `RETAINED_WITH_JUSTIFICATION`: legacy API remains only with a specific compatibility reason, scope, test coverage and removal condition.

A policy allow/retain rule may be added only after the corresponding evidence exists. No blanket API-family allowlist is permitted.

## Current gate

The 64-name matrix has official mapping sections and target manual links, but all rows remain `UNREVIEWED` and `approval=false`. The header baseline and run-bound attestation pass. The next work is to inspect the real callsite-context artifact, resolve target preprocessor reachability (especially ENGINE), then create concrete test cases per active API. No WAPP/MAPD/1905daemon source migration or Quick/Full compilation is authorized by this plan.

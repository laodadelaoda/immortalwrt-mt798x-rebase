# N60 Pro EasyMesh — OpenSSL 3.5.9 40-API semantic migration review

- Review scope: the 40 APIs classified as target-active in Quick run `42962336945`, source revision `455cd97b0581f592850629d7916dff2dcd0c92f4`.
- Evidence baseline: 348 active callsites across `wappd` and `1905daemon`; the counts below are callsite counts, not unique source files.
- This is a semantic review record, **not migration approval**. Every API remains `approval=false`; no source migration is certified by this document.
- The 68-row 1.1.1w-to-3.5.9 global candidate baseline remains unchanged and remains traceability-only.
- The reachability correction for included source files is being revalidated separately. If the corrected run changes the active set or callsite counts, this review must be reconciled against that new exact-SHA evidence before implementation approval.

## Review disposition

The 40 entries have been reviewed at API-contract level against the exact observed use patterns and the OpenSSL 3.5 migration guidance. The review identifies migration targets and non-negotiable behavioral invariants. It does **not** claim all callsites have been rewritten, nor that runtime equivalence has been proven.

| API | Active callsites | Migration review | Required semantic invariants |
|---|---:|---|---|
| `AES_set_decrypt_key` | 2 | EVP AES-WRAP decrypt initialization; Migrate with AES_unwrap_key as one operation to EVP_CIPHER_CTX + AES-{128,192,256}-WRAP. Select from KEK length; no standalone low-level key schedule. | Preserve KEK bit length, RFC 3394 wrap mode, input/output sizing, integrity-failure return and cleansing of temporary key material. |
| `AES_set_encrypt_key` | 2 | EVP AES-WRAP encrypt initialization; Migrate with AES_wrap_key to EVP AES-WRAP; do not translate to generic AES-ECB/CBC. | Preserve KEK bit length, exact wrap variant and output length; use provider-fetched AES-WRAP cipher. |
| `AES_unwrap_key` | 2 | EVP AES-WRAP decrypt operation; Use EVP_DecryptInit_ex2/Update/Final with the matching AES-WRAP cipher; do not treat unwrap as generic block decryption. | Verify RFC 3394 integrity check, wrapped input length constraints, output length, failure behavior and zeroization. |
| `AES_wrap_key` | 2 | EVP AES-WRAP encrypt operation; Use EVP_EncryptInit_ex2/Update/Final with AES-WRAP selected by 128/192/256-bit KEK. | Verify RFC 3394 vectors and no accidental padding/IV semantics; preserve the current n*8 input sizing. |
| `DES_set_key` | 2 | Conditional EVP DES-ECB via Legacy Provider; otherwise redesign/remove; The current helper expands a 7-byte key into an 8-byte DES key and feeds one 8-byte block to DES-ECB. EVP DES-ECB is in the Legacy Provider; no safe default-provider substitution exists. | Preserve bit packing and parity behavior. Do not enable Legacy globally; prove legacy.so packaging/loading and policy approval, or establish the protocol feature can be removed. |
| `DES_ecb_encrypt` | 2 | Conditional EVP DES-ECB via Legacy Provider; otherwise redesign/remove; Replace the one-block DES operation with EVP DES-ECB only if the Legacy Provider is intentionally available for this feature. | Preserve DES_ENCRYPT direction, exactly one 8-byte block, output bytes and weak-key/error semantics; add known-answer tests. |
| `DH_compute_key` | 2 | EVP_PKEY_derive; Build/import peer and local DH keys as provider-backed EVP_PKEYs, call EVP_PKEY_derive_set_peer then EVP_PKEY_derive. | Preserve raw shared-secret bytes (not an implicit KDF), peer validation, leading-zero/padding semantics, output length and error handling. |
| `DH_free` | 6 | EVP_PKEY_free / explicit ownership model; Replace low-level DH ownership with EVP_PKEY lifecycle. Treat this as part of the complete DH flow migration, not a mechanical rename. | Map every success/error exit; preserve transferred vs borrowed BIGNUM ownership, reference counts and clear-free of private material. |
| `DH_generate_key` | 4 | EVP_PKEY_keygen_init + EVP_PKEY_generate; Generate provider-backed DH/DHX keys with explicit group/parameter configuration. | Preserve p/g and DH-vs-DHX selection, validation, private/public generation and interoperability with existing peer encoding. |
| `DH_get0_key` | 2 | EVP_PKEY_get_bn_param; Read public/private values through OSSL_PKEY_PARAM_PUB_KEY / PRIV_KEY using EVP_PKEY_get_bn_param where actually required. | Returned BIGNUMs are owned copies; clear_free private values. Avoid exporting private material if the caller only needs a provider operation. |
| `DH_new` | 4 | EVP_PKEY_CTX_new_from_name / EVP_PKEY_new; Create provider-backed DH key contexts and EVP_PKEYs; do not create a mutable low-level DH object. | Preserve provider/libctx/property selection and cleanup on partial initialization. |
| `DH_set0_key` | 2 | EVP_PKEY_fromdata; Import public/private DH parameters via OSSL_PARAM and EVP_PKEY_fromdata. | Preserve old ownership-transfer behavior, parameter completeness, public/private consistency and private BIGNUM cleansing. |
| `DH_set0_pqg` | 4 | EVP_PKEY_fromdata / DH parameter OSSL_PARAMs; Import p/q/g via EVP_PKEY_fromdata; use explicit parameter names and validate the selected DH/DHX type. | Preserve p/q/g presence (including intentionally absent q), group semantics, ownership and validation; never silently substitute a named group. |
| `DH_size` | 2 | EVP_PKEY_get_size; Use EVP_PKEY_get_size for maximum shared-secret/output sizing, not EVP_PKEY_get_bits. | Confirm the target provider reports the same byte capacity for the actual imported/generated DH key. |
| `EC_GROUP_get_curve_GFp` | 2 | EC_GROUP_get_curve; Direct documented rename to EC_GROUP_get_curve. | Preserve p/a/b outputs, BN_CTX use, prime-field assumptions and return/error handling. |
| `EC_KEY_free` | 65 | EVP_PKEY_free; eliminate EC_KEY ownership; Migrate with EC_KEY_new/getters/setters and EVP_PKEY_get1_EC_KEY callsites as one provider-key refactor. | 65 frees require a full ownership map; do not replace mechanically until each pointer's origin, aliasing and transfer/refcount are known. |
| `EC_KEY_get0_group` | 24 | EVP_PKEY_get_utf8_string_param(OSSL_PKEY_PARAM_GROUP_NAME) or provider operations; Replace internal EC_GROUP pointer access with named-curve/group parameters or high-level operations. | Preserve curve identity and avoid retaining/mutating provider-internal or cached low-level objects. |
| `EC_KEY_get0_private_key` | 13 | EVP_PKEY_get_bn_param only when export is required; Prefer provider operations; if scalar extraction is genuinely required, use OSSL_PKEY_PARAM_PRIV_KEY and treat the result as an owned secret copy. | Do not create new private-key export paths; clear_free copies and verify provider/FIPS export restrictions. |
| `EC_KEY_get0_public_key` | 29 | EVP_PKEY_get_octet_string_param(OSSL_PKEY_PARAM_PUB_KEY); Read the encoded public point through provider parameters; decode to EC_POINT only where arithmetic is required. | Preserve named curve, point format, point validation and borrowed-vs-owned lifetime; do not assume compressed/uncompressed equivalence. |
| `EC_KEY_new` | 7 | EVP_PKEY_CTX_new_from_name + EVP_PKEY_fromdata/keygen; Replace low-level EC_KEY construction with provider-backed EVP_PKEY creation. | Preserve whether the object is initially empty or already carries group/key data; make every failure path free contexts and keys. |
| `EC_KEY_new_by_curve_name` | 6 | EVP_PKEY keygen/fromdata with OSSL_PKEY_PARAM_GROUP_NAME; Use the exact named-curve identifier as a provider parameter; do not substitute by curve bit size. | Preserve NID-to-group mapping, curve availability and key-generation vs public-key-import behavior. |
| `EC_KEY_set_asn1_flag` | 7 | OSSL_PKEY_PARAM_EC_ENCODING; Use provider EC encoding parameter (`named_curve` vs `explicit`) when constructing/importing the key. | Preserve named-vs-explicit parameter encoding in DER; verify DPP peer compatibility and encoded output. |
| `EC_KEY_set_conv_form` | 2 | OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT or explicit point encoding; Set provider point-conversion format or encode the public point explicitly; do not mutate a key returned by EVP_PKEY_get1_EC_KEY. | Preserve uncompressed point form currently selected before i2o_ECPublicKey; compare exact DPP wire bytes. |
| `EC_KEY_set_group` | 7 | EVP_PKEY_fromdata with OSSL_PKEY_PARAM_GROUP_NAME; Construct a new immutable provider key with the selected group rather than mutating a low-level EC_KEY. | Preserve group/point compatibility and reject mismatched curve and public-point inputs. |
| `EC_KEY_set_public_key` | 9 | EVP_PKEY_fromdata with OSSL_PKEY_PARAM_PUB_KEY; Import the public point as octets with its exact group and encoding using provider key management. | Preserve point validation, group association and public-only vs keypair selection. |
| `EC_POINT_get_affine_coordinates_GFp` | 20 | EC_POINT_get_affine_coordinates; Direct documented rename; this is still EC_POINT arithmetic, not an EVP_PKEY getter migration. | Preserve prime-field semantics, coordinate BIGNUM ownership, BN_CTX and point-at-infinity error behavior. |
| `EC_POINT_set_affine_coordinates_GFp` | 10 | EC_POINT_set_affine_coordinates; Direct documented rename. | Preserve coordinate range checks, point validation, prime-field assumption and error handling. |
| `EC_POINT_set_compressed_coordinates_GFp` | 4 | EC_POINT_set_compressed_coordinates; Direct documented rename. | Preserve y-bit parity, compressed-point decoding, curve checks and failure behavior. |
| `EVP_PKEY_cmp` | 2 | EVP_PKEY_eq; Use EVP_PKEY_eq for key equality; use EVP_PKEY_parameters_eq only if the callsite intended parameter equality. | Verify key type support and the distinction between key equality and parameter equality. |
| `EVP_PKEY_get0_EC_KEY` | 11 | Remove low-level accessor; use EVP_PKEY parameters/operations; No safe 1:1 provider-native replacement returning an EC_KEY pointer. Refactor each caller to parameter getters or high-level operations. | OpenSSL 3 provider keys may return a cached copy; never mutate it or assume changes propagate. Preserve read-only behavior. |
| `EVP_PKEY_get1_EC_KEY` | 43 | Remove low-level extraction; use EVP_PKEY parameters/operations; No safe 1:1 provider-native replacement returning a mutable EC_KEY. Replace callers by operations/parameters; use OSSL_ENCODER only for actual serialization. | 43 reference-counted extractions must be mapped to their EC_KEY_free sites. Preserve no accidental private-key export or stale cached-copy mutation. |
| `EVP_PKEY_set1_EC_KEY` | 13 | EVP_PKEY_fromdata / EVP_PKEY_todata; Replace legacy EC_KEY assignment with provider-backed parameter import; create a new immutable EVP_PKEY. | Preserve public/private components, group, encoding, ownership transfer and error behavior; do not retain a legacy key silently. |
| `HMAC_CTX_free` | 8 | EVP_MAC_CTX_free + EVP_MAC_free; Migrate the whole HMAC context lifecycle to EVP_MAC; separately own/free fetched EVP_MAC and EVP_MAC_CTX. | Cover every error exit and double-free/early-return path; preserve context lifetime and secure cleanup. |
| `HMAC_CTX_new` | 4 | EVP_MAC_fetch + EVP_MAC_CTX_new; Fetch HMAC from the intended provider/property query, create EVP_MAC_CTX and hold the fetched algorithm for the required lifetime. | Preserve default-provider selection, digest choice, failure behavior and no implicit Legacy Provider load. |
| `HMAC_Final` | 4 | EVP_MAC_final; Use EVP_MAC_final with an explicit output buffer capacity and returned output length. | Preserve digest output length, finalization-once semantics, result code mapping and cleanup if final fails. |
| `HMAC_Init_ex` | 4 | EVP_MAC_init + OSSL_MAC_PARAM_DIGEST; Set the digest name through OSSL_PARAM and initialize with the same key; model reinitialization explicitly. | Preserve NULL-key reuse semantics if relied upon, digest selection, key length, provider fetch and error handling. |
| `HMAC_Update` | 4 | EVP_MAC_update; Replace each streaming update with EVP_MAC_update. | Preserve order, exact byte lengths, zero-length behavior, chunking equivalence and propagation of update failures. |
| `d2i_ECPrivateKey` | 2 | OSSL_DECODER_from_bio / EVP_PKEY decoder, DER type-specific; Decode provider-backed EC private keys with DER and type-specific SEC1 structure; do not silently switch to PKCS#8. | Preserve SEC1 input format, full input consumption/trailing-data policy, error queue and private-key import/export policy. |
| `i2d_ECPrivateKey` | 6 | OSSL_ENCODER_to_bio, DER type-specific; Encode provider-backed EC private keys using the type-specific ECPrivateKey structure where SEC1 is required. | Preserve SEC1 rather than PKCS#8, exact DPP interoperability, output allocation/length semantics and private-key cleansing. |
| `i2o_ECPublicKey` | 4 | EVP_PKEY_get1_encoded_public_key; Use the generic encoded-public-key accessor or EVP_PKEY public-key octet parameter; preserve the requested point conversion form. | Compare exact uncompressed point bytes and length; ensure ownership/free of returned buffer and no accidental DER SubjectPublicKeyInfo substitution. |

## Cross-cutting findings and implementation order

### 1. Do not perform mechanical symbol substitution

- **AES key wrap:** the four low-level calls are paired in the same wrap/unwrap helper in both WAPP and 1905daemon. Migrate each helper atomically to EVP AES-WRAP. Generic AES-ECB/CBC is not equivalent.
- **DH:** the eight APIs form one lifecycle/key-exchange unit. Replace object creation, parameter transfer, key generation, extraction, size calculation, derive and destruction together. A line-by-line rename risks ownership bugs and changed shared-secret bytes.
- **EC/EVP_PKEY:** the 65 `EC_KEY_free` and 43 `EVP_PKEY_get1_EC_KEY` callsites make ownership the dominant risk. Build an origin-to-release map before changing lifecycle calls. Provider-backed keys are immutable; `get0/get1` accessors may expose cached copies and are read-only.
- **EC point helpers:** the three `_GFp` functions have direct generic-name replacements; keep their arithmetic and BN ownership semantics unchanged.
- **HMAC:** migrate the five HMAC calls as one EVP_MAC context lifecycle, preserving digest/key reinitialization, streaming order, output length and cleanup.
- **DPP key serialization:** `d2i_ECPrivateKey/i2d_ECPrivateKey` are SEC1 ECPrivateKey operations, not generic PKCS#8 operations. The decoder/encoder structure and exact DER bytes must be tested. `i2o_ECPublicKey` is raw EC point octets, not SubjectPublicKeyInfo DER.
- **DES:** OpenSSL 3.5 moves DES implementations to the Legacy Provider. No default-provider replacement is assumed. The project must explicitly decide whether the protocol feature is required and whether the provider module is built, packaged and loaded; do not enable Legacy globally as a convenience.

### 2. Required regression evidence before changing each family to APPROVED

1. Exact target preprocessor report with zero `UNKNOWN_FAIL_CLOSED` and a fresh exact-SHA credential.
2. RFC 3394 AES wrap/unwrap known-answer vectors for 128/192/256-bit KEKs, malformed lengths, integrity failure and cleanse paths.
3. DES known-answer vectors plus an explicit Legacy Provider packaging/loading test, or a documented protocol-level removal decision.
4. DH generated/imported key interoperability, peer validation, raw shared-secret byte-for-byte vectors, leading-zero cases and all allocation-failure paths.
5. EC named-curve, public-point encoding, SEC1 DER round-trip, point conversion and DPP interoperability tests; verify private material is not newly exported.
6. HMAC RFC vectors for every digest actually used, reinit/NULL-key behavior, multi-chunk update, output length and failure cleanup.
7. Target compilation with deprecation warnings treated as errors, followed by the separate full firmware gate only after all audits pass.

### 3. Approval policy

- Keep `migration_status=UNREVIEWED` and `approval=false` in the global baseline until implementation and regression evidence exist.
- The review status in this document means only that the semantic migration decision and its blockers have been documented.
- A provider redesign, a Legacy Provider dependency, or a behavior-changing removal requires explicit implementation evidence; none is approved by this review.
- Firmware compilation remains frozen. This review does not authorize Quick package compilation or Full firmware compilation.

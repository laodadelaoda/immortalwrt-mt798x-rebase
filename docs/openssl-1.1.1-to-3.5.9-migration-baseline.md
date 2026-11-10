# OpenSSL 1.1.1 → 3.5.9 migration baseline

Status: **baseline inventory committed for review; not an approval to migrate or suppress warnings**.

## Immutable source baseline

The compatibility comparison is pinned to the final public OpenSSL 1.1.1 release, **1.1.1w**, rather than an unspecified “1.1.1” snapshot:

- 1.1.1w archive: `openssl-1.1.1w.tar.gz`
- Official SHA256: `cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8`
- Official release announcement: [OpenSSL 1.1.1w announcement](https://mta.openssl.org/pipermail/openssl-announce/2023-September/000274.html)
- OpenSSL 3.5.9 archive: `openssl-3.5.9.tar.gz`
- Current repository `package/libs/openssl/Makefile` pin: `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`
- Current package version: `3.5.9`; official 3.5.9 release notes: [OpenSSL 3.5 Series Release Notes](https://www.openssl-library.org/news/openssl-3.5-notes/)

The 1.1.1w archive digest is published in the OpenSSL project's release announcement. The 3.5.9 digest matches the current OpenSSL package pin and public mirror checksum records. Both archive bytes still need independent CI download/hash verification; the new read-only baseline workflow performs that check before generating the header delta.

## Scope and evidence anchor

This baseline is derived from the strict API inventory artifact for GitHub Actions run [42724660705](https://github.com/laodadelaoda/immortalwrt-mt798x-rebase/actions/runs/42724660705), source revision `cd8c6ae45c01f3b671822e8f44aa26c6fbf52706`, against the pinned OpenSSL 3.5.9 public headers and the then-prepared EasyMesh source trees.

- Prepared lexical call sites: **29,929**.
- Pristine lexical call sites: **29,879**.
- OpenSSL public-header API names parsed: **2,243**.
- Deprecated API declarations found in those headers: **802**.
- Original unclassified rows: **631**; 202 were the parser false positive `int`.
- Remaining source inventory: **429 call sites across 64 distinct deprecated API names**.
- Observed components: WAPP (`wappd`) and `1905daemon`; MAPD and `libmapd` had no real deprecated call sites in this artifact.

The C-keyword parser correction is now present in the repository, but this CSV preserves the exact 64-name baseline from the earlier artifact. A new run must regenerate the inventory and prove the 202 false positives disappear without losing genuine calls.

## Normative source hierarchy

The OpenSSL 3.5 migration guide itself states that its migration coverage is currently OpenSSL 3.0 and 3.1; it is the authoritative 1.1.1-to-3.x migration framework, but it is not a complete changelog for 3.5.9-specific changes. The 3.5.9 target manuals, release notes and the pinned 3.5.9 source headers must also be consulted.

1. [OpenSSL 3.5 migration guide](https://docs.openssl.org/3.5/man7/ossl-guide-migration/) — migration policy and 1.1.1 → 3.0 architecture/API guidance.
2. [OpenSSL 3.5 EVP_MAC manual](https://docs.openssl.org/3.5/man3/EVP_MAC/) — HMAC/CMAC migration target.
3. [OpenSSL 3.5 EVP_PKEY manual](https://docs.openssl.org/3.5/man3/EVP_PKEY/) and algorithm-specific EVP manuals — key generation, access, comparison, derivation and validation.
4. [OpenSSL 3.5 Provider guide](https://docs.openssl.org/3.5/man7/provider/) and [OSSL_PROVIDER manual](https://docs.openssl.org/3.5/man3/OSSL_PROVIDER/) — ENGINE/provider architectural migration.
5. [OpenSSL 3.5 OSSL_DECODER manual](https://docs.openssl.org/3.5/man3/OSSL_DECODER/) and [OSSL_ENCODER manual](https://docs.openssl.org/3.5/man3/OSSL_ENCODER/) — key serialization.
6. [OpenSSL 3.5 release notes](https://www.openssl-library.org/news/openssl-3.5-notes/) and [release lifecycle](https://www.openssl-library.org/policies/releasestrat/) — exact target release and maintenance baseline.

OpenSSL's guide explicitly warns that deprecated low-level APIs may bypass Provider selection. The presence of a similarly named EVP API is not proof of semantic equivalence. ENGINE control, raw EC point arithmetic, legacy DES, raw SHA transform, and SEC1 serialization need special scrutiny rather than mechanical replacement.

## Verified source/header baseline

Successful read-only baseline audit: [run 42729318987](https://github.com/laodadelaoda/immortalwrt-mt798x-rebase/actions/runs/42729318987), Git SHA `8048e19987de64b0591b7f3c819586977031ab51`, attempt 1.

- Archive SHA256 verified: 1.1.1w `cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8`; 3.5.9 `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
- Header-tree SHA256: 1.1.1w `f0b4d32266cfeff08cb8096aa0d6f98a14530930bad10859ba71bac5cac18236`; 3.5.9 `f36be543eec6d91693bf38704c4b4cd2b02983b2aec258ea837a665e15b72342`.
- The 64 mapped APIs are all present in both releases; all 64 are deprecated in 3.5.9.
- Five of the 64 already carry a deprecation annotation in 1.1.1w: `EC_GROUP_get_curve_GFp`, `EC_POINT_get_affine_coordinates_GFp`, `EC_POINT_set_affine_coordinates_GFp`, `EC_POINT_set_compressed_coordinates_GFp` (marked `DEPRECATEDIN_1_2_0`) and `HMAC_Init_ex` (marked `DEPRECATEDIN_1_1_0`). The remaining 59 in this inventory are not annotated as deprecated in 1.1.1w but are deprecated in 3.5.9.
- The audit artifact binds Git SHA, run/attempt, lock/map/package Makefile/scanner/policy hashes and both source/header hashes.

This is header/API provenance evidence only. It does not prove call-site reachability, equivalent behavior or approval to change source code.

## Source reachability correction

The original 429-call lexical report included five references to `EVP_CIPHER_CTX_iv_noconst` inside WAPP's local `crypto/evp.h` macro definitions. The header is included by `dpp/dpp.c`, but the top-level macros `IMPLEMENT_BLOCK_CIPHER` and `IMPLEMENT_CFBR` are not invoked in the fixed source tree. These five references are therefore recorded as `UNREFERENCED_MACRO_DEFINITION`, not active call sites. The scanner now separates macro-body references from function-call inventory and fails closed if a deprecated API is found in an active macro expansion.

The ENGINE family is separately marked `OPENSSL_NO_ENGINE_GUARD_REQUIRES_PREPROCESSOR`: the N60 config omits `CONFIG_OPENSSL_ENGINE`, and the OpenWrt OpenSSL Makefile therefore selects `no-engine`. The actual `#if` guards and target preprocessor result must still be checked before counting those source references as active compiled calls.

## What is present today

- The exact reference versions are now declared: OpenSSL 1.1.1w → 3.5.9.

- A pinned 3.5.9 package source and a source inventory script.
- A fail-closed policy file, but its `api_rules` object is empty.
- A 64-row migration map with per-API official mapping kind/section/manual link; all rows remain UNREVIEWED.
- A lexical scanner that now requires complete mapping coverage and rejects unreviewed rows, plus a Provider smoke/runtime test.
- A read-only baseline auditor and a separate workflow to download/hash 1.1.1w and 3.5.9 and compare public-header inventories.
- A const-correctness check for a narrow `EVP_PKEY_get0_EC_KEY` pattern.
- A pristine-vs-prepared call-count delta.

## Gaps against the requested standard

1. **The 64-name research matrix now records per-API official guidance, but it is not yet reviewed.** Each row has an official migration-guide section, a target manual URL, a proposed mapping class and a call-site semantic checklist. All 64 rows remain UNREVIEWED/approval=false; the mapping is research evidence, not permission to edit or suppress the API.
2. **The source/header comparison is implemented but not yet CI-verified.** The new workflow has passed once for the 64-row header coverage and source hashes; it must continue to pass on every change to the baseline inputs.
3. **No semantic call-site review.** The inventory has component/path/line but does not capture argument expressions, return-value handling, ownership transfer, error-queue behavior, provider properties, or algorithm parameters.
4. **Lexical coverage is incomplete.** Regex scanning cannot reliably resolve macros, aliases, indirect/function-pointer calls, conditional compilation, wrappers, or type-level const/ownership. Clang AST/preprocessor evidence is required. In particular, the N60 config does not set `CONFIG_OPENSSL_ENGINE`; the OpenWrt OpenSSL Makefile therefore adds `no-engine`, while the lexical scan still sees ENGINE calls in `1905daemon`. The active/inactive preprocessor branches must be resolved before treating those calls as reachable migration work.
5. **Tests are not migration-equivalence tests.** The Provider test demonstrates a narrow Provider runtime path; it does not prove HMAC/CMAC/AES/DH/EC/RSA/ENGINE/serialization behavior matches the vendor's 1.1.1 behavior. The header-delta workflow is inventory evidence only, not a semantic regression suite.
6. **No machine-enforced approval workflow.** The policy schema does not require official reference, call-site IDs, semantic test IDs, reviewers, or evidence hashes. The empty policy is fail-closed but cannot express a reviewed migration decision.
7. **No reusable supplier-update credential.** The OpenSSL inventory is not yet bound to vendor Lock SHA256, exact source archive SHA256, OpenSSL source archive SHA256, patch-stack digest, source-tree digest, Git SHA, run/attempt, toolchain/compiler versions and test evidence hashes.
8. **Provider architecture is not inventoried.** ENGINE names, controls, hardware key loading, provider availability, default properties and algorithm fetch paths are not yet mapped to actual runtime requirements. The target OpenSSL package retains ENGINE-related build/config options, but the N60 config currently does not enable `CONFIG_OPENSSL_ENGINE`; source-level ENGINE references must be distinguished from compiled paths.
9. **Quick gate still treats the inventory as a strict warning gate, not a completed migration proof.** The new baseline must be reviewed before source changes; all 64 names remain unapproved until their own evidence is complete.

## Required workflow (no code migration before review)

For every API name and every call site:

1. Resolve the declaration and deprecation macro from the exact OpenSSL 3.5.9 headers.
2. Read the official 3.5 manual page and migration-guide section; record exact URL/section and archive/header provenance.
3. Inspect the actual vendor call site and surrounding function, including all callers where ownership/lifetime crosses a boundary.
4. Classify: `DIRECT_REPLACEMENT`, `SEMANTIC_ADAPTATION`, `NO_DIRECT_REPLACEMENT`, `LEGACY_RETAINED_WITH_JUSTIFICATION`, or `REDESIGN_REQUIRED`.
5. Record old behavior and invariants before editing: algorithm/mode/digest, key/IV lengths, encoding, padding, validation, return/error behavior, memory ownership and cleanup.
6. Define a test before changing code. Prefer known-answer vectors and differential execution against the immutable 1.1.1 reference where feasible; include malformed inputs and failure paths.
7. Only then implement the smallest source patch. Do not change the vendor patch stack merely to satisfy a scanner.
8. Re-run static AST inventory, strict Prepare, semantic tests and provider tests; retain all artifacts and bind them to a new audit credential.
9. Keep Quick compilation and Full firmware blocked until the migration gate and existing vendor/kernel gates pass.

## Decision rule

Every row in `openssl-111-to-359-migration-map.csv` is intentionally `UNREVIEWED` and `approval=false`. Candidate replacements are research leads, not approved substitutions. No blanket allowlist, warning suppression, or bulk API rewrite is permitted.

# OpenSSL 1.1.1 → 3.5.9 migration baseline

Status: **baseline inventory committed for review; not an approval to migrate or suppress warnings**.

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

1. [OpenSSL 3.5 migration guide](https://docs.openssl.org/3.5/man7/ossl-guide-migration/) — migration policy and 1.1.1 → 3.0 architecture/API guidance.
2. [OpenSSL 3.5 EVP_MAC manual](https://docs.openssl.org/3.5/man3/EVP_MAC/) — HMAC/CMAC migration target.
3. [OpenSSL 3.5 EVP_PKEY manual](https://docs.openssl.org/3.5/man3/EVP_PKEY/) and algorithm-specific EVP manuals — key generation, access, comparison, derivation and validation.
4. [OpenSSL 3.5 Provider guide](https://docs.openssl.org/3.5/man7/provider/) and [OSSL_PROVIDER manual](https://docs.openssl.org/3.5/man3/OSSL_PROVIDER/) — ENGINE/provider architectural migration.
5. [OpenSSL 3.5 OSSL_DECODER manual](https://docs.openssl.org/3.5/man3/OSSL_DECODER/) and [OSSL_ENCODER manual](https://docs.openssl.org/3.5/man3/OSSL_ENCODER/) — key serialization.
6. [OpenSSL 3.5 release notes](https://www.openssl-library.org/news/openssl-3.5-notes/) and [release lifecycle](https://www.openssl-library.org/policies/releasestrat/) — exact target release and maintenance baseline.

OpenSSL's guide explicitly warns that deprecated low-level APIs may bypass Provider selection. The presence of a similarly named EVP API is not proof of semantic equivalence. ENGINE control, raw EC point arithmetic, legacy DES, raw SHA transform, and SEC1 serialization need special scrutiny rather than mechanical replacement.

## What is present today

- A pinned 3.5.9 package source and a source inventory script.
- A fail-closed policy file, but its `api_rules` object is empty.
- A lexical scanner with a small self-test, plus a Provider smoke/runtime test.
- A const-correctness check for a narrow `EVP_PKEY_get0_EC_KEY` pattern.
- A pristine-vs-prepared call-count delta.

## Gaps against the requested standard

1. **No complete per-API official mapping.** The existing policy is empty; no API row records the exact official manual page, replacement rationale, or “no direct replacement” conclusion.
2. **No 1.1.1 source/header baseline.** The scanner only catalogs the pinned 3.5.9 headers; it does not compare against an immutable 1.1.1 reference archive or identify APIs introduced/removed between versions.
3. **No semantic call-site review.** The inventory has component/path/line but does not capture argument expressions, return-value handling, ownership transfer, error-queue behavior, provider properties, or algorithm parameters.
4. **Lexical coverage is incomplete.** Regex scanning cannot reliably resolve macros, aliases, indirect/function-pointer calls, conditional compilation, wrappers, or type-level const/ownership. Clang AST/preprocessor evidence is required.
5. **Tests are not migration-equivalence tests.** The Provider test demonstrates a narrow Provider runtime path; it does not prove HMAC/CMAC/AES/DH/EC/RSA/ENGINE/serialization behavior matches the vendor's 1.1.1 behavior.
6. **No machine-enforced approval workflow.** The policy schema does not require official reference, call-site IDs, semantic test IDs, reviewers, or evidence hashes. The empty policy is fail-closed but cannot express a reviewed migration decision.
7. **No reusable supplier-update credential.** The OpenSSL inventory is not yet bound to vendor Lock SHA256, exact source archive SHA256, OpenSSL source archive SHA256, patch-stack digest, source-tree digest, Git SHA, run/attempt, toolchain/compiler versions and test evidence hashes.
8. **Provider architecture is not inventoried.** ENGINE names, controls, hardware key loading, provider availability, default properties and algorithm fetch paths are not yet mapped to actual runtime requirements.
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

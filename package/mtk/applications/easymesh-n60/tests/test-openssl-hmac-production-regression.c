#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

typedef unsigned char u8;
#define PASS(id) puts("PASS_TEST_ID:" id)

/* Deterministic fault injection for the EVP_MAC_update error paths. */
static int test_fail_next_mac_update;

static int testable_mac_update(EVP_MAC_CTX *ctx, const u8 *data, size_t len)
{
    if (test_fail_next_mac_update) {
        test_fail_next_mac_update = 0;
        return 0;
    }
    return EVP_MAC_update(ctx, data, len);
}

static EVP_MAC_CTX * openssl_hmac_ctx_new(const EVP_MD *md, const u8 *key,
                                         size_t key_len)
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    const char *md_name;

    if (!md || !key)
        return NULL;
    md_name = EVP_MD_get0_name(md);
    if (!md_name)
        return NULL;
    mac = EVP_MAC_fetch(NULL, "HMAC", "provider=default");
    if (!mac)
        return NULL;
    ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx)
        return NULL;
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                  (char *) md_name, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(ctx, key, key_len, params) != 1) {
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int openssl_hmac_vector(const EVP_MD *md, const u8 *key,
                               size_t key_len, size_t num_elem,
                               const u8 *addr[], const size_t *len,
                               u8 *out, size_t out_size)
{
    EVP_MAC_CTX *ctx;
    size_t i, out_len = 0;
    int res;

    ctx = openssl_hmac_ctx_new(md, key, key_len);
    if (!ctx)
        return -1;
    for (i = 0; i < num_elem; i++) {
        if (testable_mac_update(ctx, addr[i], len[i]) != 1) {
            EVP_MAC_CTX_free(ctx);
            return -1;
        }
    }
    res = EVP_MAC_final(ctx, out, &out_len, out_size);
    EVP_MAC_CTX_free(ctx);
    return res == 1 && out_len == out_size ? 0 : -1;
}

enum crypto_hash_alg {
    CRYPTO_HASH_ALG_HMAC_MD5,
    CRYPTO_HASH_ALG_HMAC_SHA1,
    CRYPTO_HASH_ALG_HMAC_SHA256
};

struct crypto_hash {
    EVP_MAC_CTX *ctx;
    int failed;
};

static struct crypto_hash *crypto_hash_init(enum crypto_hash_alg alg,
                                             const u8 *key, size_t key_len)
{
    const EVP_MD *md = NULL;
    struct crypto_hash *ctx;

    switch (alg) {
    case CRYPTO_HASH_ALG_HMAC_MD5:
        md = EVP_md5();
        break;
    case CRYPTO_HASH_ALG_HMAC_SHA1:
        md = EVP_sha1();
        break;
    case CRYPTO_HASH_ALG_HMAC_SHA256:
        md = EVP_sha256();
        break;
    }
    if (!md)
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->ctx = openssl_hmac_ctx_new(md, key, key_len);
    if (!ctx->ctx) {
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return NULL;
    }
    return ctx;
}

static void crypto_hash_update(struct crypto_hash *ctx, const u8 *data,
                               size_t len)
{
    if (ctx == NULL)
        return;
    if (testable_mac_update(ctx->ctx, data, len) != 1)
        ctx->failed = 1;
}

static int crypto_hash_finish(struct crypto_hash *ctx, u8 *mac, size_t *len)
{
    size_t mdlen = 0, required;
    int res;

    if (ctx == NULL)
        return -2;
    if (mac == NULL || len == NULL) {
        EVP_MAC_CTX_free(ctx->ctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return 0;
    }
    if (ctx->failed) {
        EVP_MAC_CTX_free(ctx->ctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return -2;
    }
    required = EVP_MAC_CTX_get_mac_size(ctx->ctx);
    if (required == 0) {
        EVP_MAC_CTX_free(ctx->ctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return -2;
    }
    if (*len < required) {
        *len = required;
        EVP_MAC_CTX_free(ctx->ctx);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
        return -1;
    }
    res = EVP_MAC_final(ctx->ctx, mac, &mdlen, *len);
    EVP_MAC_CTX_free(ctx->ctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
    if (res == 1) {
        *len = mdlen;
        return 0;
    }
    return -2;
}

static int check_vector(const EVP_MD *md, const u8 *key, size_t key_len,
                        const u8 *data, size_t data_len,
                        const u8 *expected, size_t expected_len)
{
    const u8 *parts[2] = { data, data + data_len / 2 };
    size_t lengths[2] = { data_len / 2, data_len - data_len / 2 };
    u8 out[EVP_MAX_MD_SIZE] = {0};
    int ok = openssl_hmac_vector(md, key, key_len, 2, parts, lengths,
                                 out, expected_len) == 0 &&
             memcmp(out, expected, expected_len) == 0;
    OPENSSL_cleanse(out, sizeof(out));
    return ok;
}

int main(void)
{
    static const u8 key[] = "key";
    static const u8 message[] = "The quick brown fox jumps over the lazy dog";
    static const u8 sha256_expected[32] = {
        0xf7,0xbc,0x83,0xf4,0x30,0x53,0x84,0x24,
        0xb1,0x32,0x98,0xe6,0xaa,0x6f,0xb1,0x43,
        0xef,0x4d,0x59,0xa1,0x49,0x46,0x17,0x59,
        0x97,0x47,0x9d,0xbc,0x2d,0x1a,0x3c,0xd8
    };
    static const u8 sha1_key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static const u8 md5_key[16] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static const u8 hi_there[] = "Hi There";
    static const u8 sha1_expected[20] = {
        0xb6,0x17,0x31,0x86,0x55,0x05,0x72,0x64,0xe2,0x8b,
        0xc0,0xb6,0xfb,0x37,0x8c,0x8e,0xf1,0x46,0xbe,0x00
    };
    static const u8 md5_expected[16] = {
        0x92,0x94,0x72,0x7a,0x36,0x38,0xbb,0x1c,
        0x13,0xf4,0x8e,0xf8,0x15,0x8b,0xfc,0x9d
    };
    static const u8 empty_sha256[32] = {
        0xb6,0x13,0x67,0x9a,0x08,0x14,0xd9,0xec,
        0x77,0x2f,0x95,0xd7,0x78,0xc3,0x5f,0xc5,
        0xff,0x16,0x97,0xc4,0x93,0x71,0x56,0x53,
        0xc6,0xc7,0x12,0x14,0x42,0x92,0xc5,0xad
    };
    u8 empty_key = 0;
    const u8 *empty_parts[1] = { (const u8 *) "" };
    const size_t empty_lengths[1] = { 0 };
    u8 empty_out[32] = {0};
    int ok = 1;

    if (!check_vector(EVP_sha256(), key, sizeof(key) - 1,
                      message, sizeof(message) - 1,
                      sha256_expected, sizeof(sha256_expected)))
        ok = 0;
    if (!check_vector(EVP_sha1(), sha1_key, sizeof(sha1_key),
                      hi_there, sizeof(hi_there) - 1,
                      sha1_expected, sizeof(sha1_expected)))
        ok = 0;
    if (!check_vector(EVP_md5(), md5_key, sizeof(md5_key),
                      hi_there, sizeof(hi_there) - 1,
                      md5_expected, sizeof(md5_expected)))
        ok = 0;
    if (openssl_hmac_ctx_new(EVP_sha256(), NULL, 0) != NULL)
        ok = 0;
    if (openssl_hmac_vector(EVP_sha256(), &empty_key, 0, 1,
                            empty_parts, empty_lengths, empty_out,
                            sizeof(empty_out)) != 0 ||
        memcmp(empty_out, empty_sha256, sizeof(empty_sha256)) != 0)
        ok = 0;

    {
        struct crypto_hash *ctx = crypto_hash_init(CRYPTO_HASH_ALG_HMAC_SHA256,
                                                   key, sizeof(key) - 1);
        u8 wrapped[32] = {0};
        size_t wrapped_len = 0;
        if (!ctx) {
            ok = 0;
        } else {
            crypto_hash_update(ctx, message, 10);
            crypto_hash_update(ctx, message + 10, sizeof(message) - 1 - 10);
            if (crypto_hash_finish(ctx, wrapped, &wrapped_len) != 0 ||
                wrapped_len != sizeof(sha256_expected) ||
                memcmp(wrapped, sha256_expected, sizeof(sha256_expected)) != 0)
                ok = 0;
        }
        OPENSSL_cleanse(wrapped, sizeof(wrapped));
    }
    if (crypto_hash_init(CRYPTO_HASH_ALG_HMAC_SHA256, NULL, 0) != NULL)
        ok = 0;
    {
        struct crypto_hash *ctx = crypto_hash_init(CRYPTO_HASH_ALG_HMAC_SHA256,
                                                   key, sizeof(key) - 1);
        u8 failed_out[32] = {0};
        size_t failed_len = sizeof(failed_out);
        if (!ctx) {
            ok = 0;
        } else {
            test_fail_next_mac_update = 1;
            crypto_hash_update(ctx, message, sizeof(message) - 1);
            if (crypto_hash_finish(ctx, failed_out, &failed_len) != -2)
                ok = 0;
        }
        OPENSSL_cleanse(failed_out, sizeof(failed_out));
    }
    {
        u8 failed_out[32] = {0};
        test_fail_next_mac_update = 1;
        if (openssl_hmac_vector(EVP_sha256(), key, sizeof(key) - 1,
                                1, (const u8 *[]) { message },
                                (const size_t[]) { sizeof(message) - 1 },
                                failed_out, sizeof(failed_out)) != -1)
            ok = 0;
        OPENSSL_cleanse(failed_out, sizeof(failed_out));
    }
    {
        struct crypto_hash *ctx = crypto_hash_init(CRYPTO_HASH_ALG_HMAC_SHA256,
                                                   key, sizeof(key) - 1);
        u8 short_out[16] = {0};
        size_t short_len = sizeof(short_out);
        if (!ctx || crypto_hash_finish(ctx, short_out, &short_len) != -1 ||
            short_len != sizeof(sha256_expected))
            ok = 0;
        OPENSSL_cleanse(short_out, sizeof(short_out));
    }
    {
        struct crypto_hash *ctx = crypto_hash_init(CRYPTO_HASH_ALG_HMAC_SHA256,
                                                   &empty_key, 0);
        if (!ctx || crypto_hash_finish(ctx, NULL, NULL) != 0)
            ok = 0;
    }
    OPENSSL_cleanse(empty_out, sizeof(empty_out));
    if (!ok) {
        puts("FAIL: EVP_MAC production HMAC digest/key/vector semantics");
        return 1;
    }
    PASS("hmac_evp_mac_production_digest_key_vector");
    return 0;
}

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>

#define C(x) do { if (!(x)) { fprintf(stderr, "FAIL: %s\\n", #x); goto out; } } while (0)

static int test_rsa_asn1_mapping(void)
{
    EVP_PKEY_CTX *kg = NULL;
    EVP_PKEY *rsa = NULL;
    OSSL_ENCODER_CTX *encoder = NULL;
    unsigned char *der = NULL;
    size_t der_len = 0;
    unsigned int bits = 2048;
    OSSL_PARAM params[2];
    SSL_CTX *ctx = NULL, *legacy_ctx = NULL;
    SSL *generic_ssl = NULL, *legacy_ssl = NULL;
    SSL *bad_generic_ssl = NULL, *bad_legacy_ssl = NULL;
    OSSL_LIB_CTX *legacy_libctx = NULL;
    OSSL_PROVIDER *null_provider = NULL;
    const EVP_PKEY *generic_key, *legacy_key;
    int old_ret, new_bad, old_bad, ok = 0;
    unsigned long new_error, old_error;

    kg = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=default");
    C(kg != NULL && EVP_PKEY_keygen_init(kg) > 0);
    params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits);
    params[1] = OSSL_PARAM_construct_end();
    C(EVP_PKEY_CTX_set_params(kg, params) > 0);
    C(EVP_PKEY_generate(kg, &rsa) > 0 && rsa != NULL);

    encoder = OSSL_ENCODER_CTX_new_for_pkey(rsa, EVP_PKEY_KEYPAIR,
                                             "DER", "type-specific",
                                             "provider=default");
    C(encoder != NULL && OSSL_ENCODER_to_data(encoder, &der, &der_len) > 0);
    C(der != NULL && der_len > 8 && der_len <= (size_t)LONG_MAX);

    /* Provider-decoder path: compare the generic API with the deprecated
     * RSA-specific reference API. The warning suppression is local to this
     * test-only reference call; production sources retain -Werror. */
    ctx = SSL_CTX_new(TLS_method());
    C(ctx != NULL);
    generic_ssl = SSL_new(ctx);
    legacy_ssl = SSL_new(ctx);
    C(generic_ssl != NULL && legacy_ssl != NULL);
    C(SSL_use_PrivateKey_ASN1(EVP_PKEY_RSA, generic_ssl, der,
                              (long)der_len) == 1);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    old_ret = SSL_use_RSAPrivateKey_ASN1(legacy_ssl, der, (long)der_len);
#pragma GCC diagnostic pop
    C(old_ret == 1);
    generic_key = SSL_get0_privatekey(generic_ssl);
    legacy_key = SSL_get0_privatekey(legacy_ssl);
    C(generic_key != NULL && legacy_key != NULL);
    C(EVP_PKEY_eq(generic_key, legacy_key) == 1);
    C(EVP_PKEY_get_bits(generic_key) == 2048 &&
      EVP_PKEY_get_bits(legacy_key) == 2048);

    /* No default decoder: the generic API must fall back to the same legacy
     * d2i_RSAPrivateKey path used by the deprecated wrapper. */
    legacy_libctx = OSSL_LIB_CTX_new();
    C(legacy_libctx != NULL);
    null_provider = OSSL_PROVIDER_load(legacy_libctx, "null");
    C(null_provider != NULL);
    legacy_ctx = SSL_CTX_new_ex(legacy_libctx, NULL, TLS_method());
    C(legacy_ctx != NULL);
    bad_generic_ssl = SSL_new(legacy_ctx);
    bad_legacy_ssl = SSL_new(legacy_ctx);
    C(bad_generic_ssl != NULL && bad_legacy_ssl != NULL);
    C(SSL_use_PrivateKey_ASN1(EVP_PKEY_RSA, bad_generic_ssl, der,
                              (long)der_len) == 1);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    old_ret = SSL_use_RSAPrivateKey_ASN1(bad_legacy_ssl, der, (long)der_len);
#pragma GCC diagnostic pop
    C(old_ret == 1);
    generic_key = SSL_get0_privatekey(bad_generic_ssl);
    legacy_key = SSL_get0_privatekey(bad_legacy_ssl);
    C(generic_key != NULL && legacy_key != NULL);
    C(EVP_PKEY_eq(generic_key, legacy_key) == 1);

    /* Both APIs must reject truncated DER and leave an error on the queue. */
    ERR_clear_error();
    new_bad = SSL_use_PrivateKey_ASN1(EVP_PKEY_RSA, generic_ssl, der,
                                      (long)der_len - 1);
    new_error = ERR_peek_last_error();
    ERR_clear_error();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    old_bad = SSL_use_RSAPrivateKey_ASN1(legacy_ssl, der,
                                         (long)der_len - 1);
#pragma GCC diagnostic pop
    old_error = ERR_peek_last_error();
    C(new_bad == 0 && old_bad == 0 && new_error != 0 && old_error != 0);
    puts("PASS: RSA PKCS#1 DER generic/legacy equivalence, provider and legacy decoder paths, and truncated-input failure.");
    ok = 1;
out:
    ERR_clear_error();
    SSL_free(generic_ssl);
    SSL_free(legacy_ssl);
    SSL_free(bad_generic_ssl);
    SSL_free(bad_legacy_ssl);
    SSL_CTX_free(ctx);
    SSL_CTX_free(legacy_ctx);
    OSSL_PROVIDER_unload(null_provider);
    OSSL_LIB_CTX_free(legacy_libctx);
    OSSL_ENCODER_CTX_free(encoder);
    OPENSSL_free(der);
    EVP_PKEY_free(rsa);
    EVP_PKEY_CTX_free(kg);
    return ok;
}

int main(void)
{
    OSSL_PROVIDER *p = NULL;
    EVP_MD *md = NULL;
    EVP_CIPHER *ci = NULL;
    EVP_PKEY_CTX *kg = NULL, *sp = NULL, *vp = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *s = NULL, *v = NULL;
    EVP_CIPHER_CTX *e = NULL, *d = NULL;
    unsigned char *sig = NULL;
    size_t sl = 0;
    unsigned char k[16] = {0}, iv[12] = {0}, tag[16];
    unsigned char msg[] = "N60 OpenSSL 3 Provider regression", ct[128], pt[128];
    int n = 0, total = 0, tail = 0, rc = 1;
    char group[] = "prime256v1";
    OSSL_PARAM ps[2];

    p = OSSL_PROVIDER_load(NULL, "default");
    C(p != NULL);
    md = EVP_MD_fetch(NULL, "SHA256", "provider=default");
    ci = EVP_CIPHER_fetch(NULL, "AES-128-GCM", "provider=default");
    C(md != NULL && ci != NULL);
    kg = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=default");
    C(kg != NULL && EVP_PKEY_keygen_init(kg) > 0);
    ps[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                              group, 0);
    ps[1] = OSSL_PARAM_construct_end();
    C(EVP_PKEY_CTX_set_params(kg, ps) > 0 &&
      EVP_PKEY_generate(kg, &key) > 0);
    s = EVP_MD_CTX_new();
    v = EVP_MD_CTX_new();
    C(s != NULL && v != NULL &&
      EVP_DigestSignInit(s, &sp, md, NULL, key) > 0 &&
      EVP_DigestSignUpdate(s, msg, sizeof(msg) - 1) > 0 &&
      EVP_DigestSignFinal(s, NULL, &sl) > 0);
    sig = OPENSSL_malloc(sl);
    C(sig != NULL && EVP_DigestSignFinal(s, sig, &sl) > 0);
    C(EVP_DigestVerifyInit(v, &vp, md, NULL, key) > 0 &&
      EVP_DigestVerifyUpdate(v, msg, sizeof(msg) - 1) > 0 &&
      EVP_DigestVerifyFinal(v, sig, sl) == 1);
    e = EVP_CIPHER_CTX_new();
    d = EVP_CIPHER_CTX_new();
    C(e != NULL && d != NULL &&
      EVP_EncryptInit_ex2(e, ci, k, iv, NULL) > 0 &&
      EVP_EncryptUpdate(e, ct, &n, msg, sizeof(msg) - 1) > 0);
    total = n;
    C(EVP_EncryptFinal_ex(e, ct + total, &tail) > 0 &&
      EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), tag) > 0);
    total += tail;
    C(EVP_DecryptInit_ex2(d, ci, k, iv, NULL) > 0 &&
      EVP_DecryptUpdate(d, pt, &n, ct, total) > 0 &&
      EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_AEAD_SET_TAG, sizeof(tag), tag) > 0 &&
      EVP_DecryptFinal_ex(d, pt + n, &tail) > 0);
    C((size_t)(n + tail) == sizeof(msg) - 1 &&
      memcmp(pt, msg, sizeof(msg) - 1) == 0);
    C(test_rsa_asn1_mapping());
    puts("PASS: default Provider SHA256/AES-GCM, P-256 keygen and ECDSA sign/verify.");
    rc = 0;
out:
    OPENSSL_free(sig);
    EVP_CIPHER_CTX_free(e);
    EVP_CIPHER_CTX_free(d);
    EVP_MD_CTX_free(s);
    EVP_MD_CTX_free(v);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kg);
    EVP_MD_free(md);
    EVP_CIPHER_free(ci);
    OSSL_PROVIDER_unload(p);
    return rc;
}

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL: %s:%d: %s (openssl=%s)\n", __FILE__, __LINE__, #x, ERR_error_string(ERR_peek_last_error(), NULL)); goto out; } } while (0)
#define PASS(id) puts("PASS_TEST_ID:" id)
static int test_aes_wrap(void) {
 static const unsigned char kek[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
 static const unsigned char plain[16]={0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
 static const unsigned char expected[24]={0x1f,0xa6,0x8b,0x0a,0x81,0x12,0xb4,0x47,0xae,0xf3,0x4b,0xd8,0xfb,0x5a,0x7b,0x82,0x9d,0x3e,0x86,0x23,0x71,0xd2,0xcf,0xe5};
 EVP_CIPHER *cipher=NULL; EVP_CIPHER_CTX *ctx=NULL; unsigned char wrapped[32],recovered[32],tampered[24]; int n=0,total=0,tail=0,ok=0;
 cipher=EVP_CIPHER_fetch(NULL,"AES-128-WRAP","provider=default"); ctx=EVP_CIPHER_CTX_new(); CHECK(cipher&&ctx);
 EVP_CIPHER_CTX_set_flags(ctx,EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
 CHECK(EVP_EncryptInit_ex2(ctx,cipher,kek,NULL,NULL)>0); CHECK(EVP_EncryptUpdate(ctx,wrapped,&n,plain,sizeof(plain))>0); total=n;
 CHECK(EVP_EncryptFinal_ex(ctx,wrapped+total,&tail)>0); total+=tail;
 CHECK(total==(int)sizeof(expected)&&memcmp(wrapped,expected,sizeof(expected))==0);
 EVP_CIPHER_CTX_reset(ctx); EVP_CIPHER_CTX_set_flags(ctx,EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
 CHECK(EVP_DecryptInit_ex2(ctx,cipher,kek,NULL,NULL)>0); CHECK(EVP_DecryptUpdate(ctx,recovered,&n,wrapped,total)>0); total=n;
 CHECK(EVP_DecryptFinal_ex(ctx,recovered+total,&tail)>0); total+=tail;
 CHECK(total==(int)sizeof(plain)&&memcmp(recovered,plain,sizeof(plain))==0);
 memcpy(tampered,expected,sizeof(tampered)); tampered[23]^=1; EVP_CIPHER_CTX_reset(ctx); EVP_CIPHER_CTX_set_flags(ctx,EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
 CHECK(EVP_DecryptInit_ex2(ctx,cipher,kek,NULL,NULL)>0);
 { int u=EVP_DecryptUpdate(ctx,recovered,&n,tampered,sizeof(tampered)); int f=u>0?EVP_DecryptFinal_ex(ctx,recovered+n,&tail):0; CHECK(u==0||f==0); }
 ok=1; PASS("aes_wrap_rfc3394_vector_roundtrip_integrity");
out: EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(cipher); ERR_clear_error(); return ok;
}
static void expand_des_56_key(const unsigned char in[7],unsigned char out[8]) {
 out[0]=in[0]&0xfe; out[1]=(unsigned char)(((in[0]<<7)|(in[1]>>1))&0xfe); out[2]=(unsigned char)(((in[1]<<6)|(in[2]>>2))&0xfe);
 out[3]=(unsigned char)(((in[2]<<5)|(in[3]>>3))&0xfe); out[4]=(unsigned char)(((in[3]<<4)|(in[4]>>4))&0xfe);
 out[5]=(unsigned char)(((in[4]<<3)|(in[5]>>5))&0xfe); out[6]=(unsigned char)(((in[5]<<2)|(in[6]>>6))&0xfe); out[7]=(unsigned char)((in[6]<<1)&0xfe);
 for(size_t i=0;i<8;i++) out[i]|=(unsigned char)(__builtin_parity((unsigned int)(out[i]&0xfe))?0:1);
}
static int test_des_legacy(void) {
 static const unsigned char k56[7]={0x12,0x69,0x5b,0xc9,0xb7,0xb7,0xf8}, ek[8]={0x13,0x34,0x57,0x79,0x9b,0xbc,0xdf,0xf1};
 static const unsigned char plain[8]={1,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}, expected[8]={0x85,0xe8,0x13,0x54,0x0f,0x0a,0xb4,0x05};
 OSSL_PROVIDER *legacy=NULL; EVP_CIPHER *cipher=NULL; EVP_CIPHER_CTX *ctx=NULL; unsigned char key[8],out[16]; int n=0,total=0,tail=0,ok=0;
 expand_des_56_key(k56,key); CHECK(memcmp(key,ek,sizeof(key))==0); legacy=OSSL_PROVIDER_load(NULL,"legacy"); CHECK(legacy);
 cipher=EVP_CIPHER_fetch(NULL,"DES-ECB","provider=legacy"); ctx=EVP_CIPHER_CTX_new(); CHECK(cipher&&ctx);
 CHECK(EVP_EncryptInit_ex2(ctx,cipher,key,NULL,NULL)>0); CHECK(EVP_CIPHER_CTX_set_padding(ctx,0)>0);
 CHECK(EVP_EncryptUpdate(ctx,out,&n,plain,sizeof(plain))>0); total=n; CHECK(EVP_EncryptFinal_ex(ctx,out+total,&tail)>0); total+=tail;
 CHECK(total==(int)sizeof(expected)&&memcmp(out,expected,sizeof(expected))==0);
 ok=1; PASS("des_7byte_key_expansion_and_legacy_provider_known_answer");
out: EVP_CIPHER_CTX_free(ctx); EVP_CIPHER_free(cipher); if(legacy) OSSL_PROVIDER_unload(legacy); OPENSSL_cleanse(key,sizeof(key)); ERR_clear_error(); return ok;
}
static int make_dh(EVP_PKEY **out) {
 EVP_PKEY_CTX *ctx=NULL; char group[]="ffdhe2048"; OSSL_PARAM p[2]; int ok=0;
 ctx=EVP_PKEY_CTX_new_from_name(NULL,"DH","provider=default"); if(!ctx||EVP_PKEY_keygen_init(ctx)<=0) goto done;
 p[0]=OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,group,0); p[1]=OSSL_PARAM_construct_end();
 if(EVP_PKEY_CTX_set_params(ctx,p)<=0||EVP_PKEY_generate(ctx,out)<=0) goto done; ok=1;
done: EVP_PKEY_CTX_free(ctx); return ok;
}
static int derive(EVP_PKEY *local,EVP_PKEY *peer,unsigned char *secret,size_t *len) {
 EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_from_pkey(NULL,local,"provider=default"); int ok=0;
 if(!ctx||EVP_PKEY_derive_init(ctx)<=0||EVP_PKEY_derive_set_peer(ctx,peer)<=0||EVP_PKEY_derive(ctx,NULL,len)<=0||*len>512||EVP_PKEY_derive(ctx,secret,len)<=0) goto done;
 ok=1;
done: EVP_PKEY_CTX_free(ctx); return ok;
}
static int test_dh_provider(void) {
 EVP_PKEY *a=NULL,*b=NULL,*imported=NULL; EVP_PKEY_CTX *ctx=NULL; OSSL_PARAM *params=NULL; BIGNUM *pub=NULL,*priv=NULL;
 unsigned char sa[512],sb[512]; size_t la=sizeof(sa),lb=sizeof(sb); int ok=0;
 CHECK(make_dh(&a)&&make_dh(&b)); CHECK(EVP_PKEY_get_size(a)>0);
 CHECK(EVP_PKEY_get_bn_param(a,OSSL_PKEY_PARAM_PUB_KEY,&pub)>0&&pub); CHECK(EVP_PKEY_get_bn_param(a,OSSL_PKEY_PARAM_PRIV_KEY,&priv)>0&&priv);
 CHECK(derive(a,b,sa,&la)&&derive(b,a,sb,&lb)); CHECK(la==lb&&memcmp(sa,sb,la)==0);
 CHECK(EVP_PKEY_todata(a,EVP_PKEY_KEYPAIR,&params)>0&&params);
 ctx=EVP_PKEY_CTX_new_from_name(NULL,"DH","provider=default"); CHECK(ctx&&EVP_PKEY_fromdata_init(ctx)>0);
 CHECK(EVP_PKEY_fromdata(ctx,&imported,EVP_PKEY_KEYPAIR,params)>0&&imported); CHECK(EVP_PKEY_get_size(imported)==EVP_PKEY_get_size(a));
 ok=1; PASS("dh_provider_keygen_derive_params_ownership_size");
out: OPENSSL_cleanse(sa,sizeof(sa)); OPENSSL_cleanse(sb,sizeof(sb)); BN_clear_free(priv); BN_free(pub); OSSL_PARAM_free(params);
 EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(imported); EVP_PKEY_free(a); EVP_PKEY_free(b); ERR_clear_error(); return ok;
}
static int test_ec_provider(void) {
 EVP_PKEY_CTX *kg=NULL,*impctx=NULL; EVP_PKEY *key=NULL,*pubkey=NULL,*copy=NULL,*decoded=NULL; OSSL_PARAM p[4],*keyparams=NULL;
 OSSL_ENCODER_CTX *enc=NULL; OSSL_DECODER_CTX *dec=NULL; unsigned char group[]="prime256v1",*pub=NULL,*der=NULL,*encoded_pub=NULL;
 size_t publen=0,derlen=0,encoded_len=0,der_remaining=0; const unsigned char *der_cursor=NULL; char group_out[80]; size_t group_len=0; BIGNUM *priv=NULL; int ok=0;
 kg=EVP_PKEY_CTX_new_from_name(NULL,"EC","provider=default"); CHECK(kg&&EVP_PKEY_keygen_init(kg)>0);
 p[0]=OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,(char *)group,0);
 p[1]=OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING,"named_curve",0);
 p[2]=OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,"uncompressed",0); p[3]=OSSL_PARAM_construct_end();
 CHECK(EVP_PKEY_CTX_set_params(kg,p)>0&&EVP_PKEY_generate(kg,&key)>0);
 CHECK(EVP_PKEY_get_utf8_string_param(key,OSSL_PKEY_PARAM_GROUP_NAME,group_out,sizeof(group_out),&group_len)>0&&strcmp(group_out,"prime256v1")==0);
 CHECK(EVP_PKEY_get_octet_string_param(key,OSSL_PKEY_PARAM_PUB_KEY,NULL,0,&publen)>0&&publen>0); pub=OPENSSL_malloc(publen); CHECK(pub);
 CHECK(EVP_PKEY_get_octet_string_param(key,OSSL_PKEY_PARAM_PUB_KEY,pub,publen,&publen)>0);
 CHECK(EVP_PKEY_get_bn_param(key,OSSL_PKEY_PARAM_PRIV_KEY,&priv)>0&&priv);
 encoded_len=EVP_PKEY_get1_encoded_public_key(key,&encoded_pub); CHECK(encoded_len>0&&encoded_pub&&encoded_len==publen&&memcmp(pub,encoded_pub,encoded_len)==0);
 p[0]=OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,(char *)group,0); p[1]=OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,pub,publen); p[2]=OSSL_PARAM_construct_end();
 impctx=EVP_PKEY_CTX_new_from_name(NULL,"EC","provider=default"); CHECK(impctx&&EVP_PKEY_fromdata_init(impctx)>0);
 CHECK(EVP_PKEY_fromdata(impctx,&pubkey,EVP_PKEY_PUBLIC_KEY,p)>0&&pubkey); CHECK(EVP_PKEY_eq(key,pubkey)==1&&EVP_PKEY_parameters_eq(key,pubkey)==1);
 copy=EVP_PKEY_dup(key); CHECK(copy&&EVP_PKEY_eq(key,copy)==1);
 enc=OSSL_ENCODER_CTX_new_for_pkey(key,EVP_PKEY_KEYPAIR,"DER","type-specific","provider=default"); CHECK(enc&&OSSL_ENCODER_to_data(enc,&der,&derlen)>0&&derlen>0);
 dec=OSSL_DECODER_CTX_new_for_pkey(&decoded,"DER","type-specific","EC",EVP_PKEY_KEYPAIR,NULL,"provider=default");
 der_cursor=der; der_remaining=derlen; CHECK(dec&&OSSL_DECODER_from_data(dec,&der_cursor,&der_remaining)>0&&der_remaining==0);
 CHECK(decoded&&EVP_PKEY_eq(key,decoded)==1); CHECK(EVP_PKEY_todata(key,EVP_PKEY_KEYPAIR,&keyparams)>0&&keyparams);
 ok=1; PASS("ec_provider_key_lifecycle_params_point_encoding_sec1_der");
out: BN_clear_free(priv); OSSL_PARAM_free(keyparams); OSSL_DECODER_CTX_free(dec); OSSL_ENCODER_CTX_free(enc);
 OPENSSL_free(encoded_pub); OPENSSL_free(pub); OPENSSL_free(der); EVP_PKEY_free(decoded); EVP_PKEY_free(copy); EVP_PKEY_free(pubkey); EVP_PKEY_free(key);
 EVP_PKEY_CTX_free(impctx); EVP_PKEY_CTX_free(kg); ERR_clear_error(); return ok;
}
static int test_ec_point_renames(void) {
 EC_GROUP *group=NULL; EC_POINT *p=NULL,*q=NULL,*r=NULL; BN_CTX *ctx=NULL; BIGNUM *x=NULL,*y=NULL,*a=NULL,*b=NULL,*prime=NULL; int ok=0;
 group=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); ctx=BN_CTX_new(); p=EC_POINT_new(group); q=EC_POINT_new(group); r=EC_POINT_new(group);
 x=BN_new(); y=BN_new(); a=BN_new(); b=BN_new(); prime=BN_new(); CHECK(group&&ctx&&p&&q&&r&&x&&y&&a&&b&&prime);
 CHECK(EC_GROUP_get_curve(group,prime,a,b,ctx)>0); CHECK(EC_POINT_mul(group,p,BN_value_one(),NULL,NULL,ctx)>0);
 CHECK(EC_POINT_get_affine_coordinates(group,p,x,y,ctx)>0); CHECK(EC_POINT_set_affine_coordinates(group,q,x,y,ctx)>0); CHECK(EC_POINT_cmp(group,p,q,ctx)==0);
 CHECK(EC_POINT_set_compressed_coordinates(group,r,x,BN_is_odd(y),ctx)>0); CHECK(EC_POINT_cmp(group,p,r,ctx)==0);
 ok=1; PASS("ec_group_curve_and_point_affine_compressed_compatibility");
out: BN_free(prime); BN_free(a); BN_free(b); BN_free(x); BN_free(y); EC_POINT_free(p); EC_POINT_free(q); EC_POINT_free(r); EC_GROUP_free(group); BN_CTX_free(ctx); ERR_clear_error(); return ok;
}
static int test_hmac_evp_mac(void) {
 static const unsigned char expected[32]={0xf7,0xbc,0x83,0xf4,0x30,0x53,0x84,0x24,0xb1,0x32,0x98,0xe6,0xaa,0x6f,0xb1,0x43,0xef,0x4d,0x59,0xa1,0x49,0x46,0x17,0x59,0x97,0x47,0x9d,0xbc,0x2d,0x1a,0x3c,0xd8};
 const unsigned char key[]="key",msg[]="The quick brown fox jumps over the lazy dog"; EVP_MAC *mac=NULL; EVP_MAC_CTX *ctx=NULL; OSSL_PARAM p[2];
 unsigned char out[EVP_MAX_MD_SIZE]; size_t outlen=0; int ok=0; mac=EVP_MAC_fetch(NULL,"HMAC","provider=default"); CHECK(mac); ctx=EVP_MAC_CTX_new(mac); CHECK(ctx);
 p[0]=OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,"SHA256",0); p[1]=OSSL_PARAM_construct_end();
 CHECK(EVP_MAC_init(ctx,key,sizeof(key)-1,p)>0); CHECK(EVP_MAC_update(ctx,msg,sizeof(msg)-1)>0); CHECK(EVP_MAC_final(ctx,out,&outlen,sizeof(out))>0);
 CHECK(outlen==sizeof(expected)&&memcmp(out,expected,sizeof(expected))==0);
 CHECK(EVP_MAC_init(ctx,key,sizeof(key)-1,p)>0); CHECK(EVP_MAC_update(ctx,msg,sizeof(msg)-1)>0); CHECK(EVP_MAC_final(ctx,out,&outlen,sizeof(out))>0&&outlen==sizeof(expected));
 ok=1; PASS("hmac_evp_mac_lifecycle_reinit_update_final");
out: OPENSSL_cleanse(out,sizeof(out)); EVP_MAC_CTX_free(ctx); EVP_MAC_free(mac); ERR_clear_error(); return ok;
}
int main(void) {
 if(!test_aes_wrap()||!test_des_legacy()||!test_dh_provider()||!test_ec_provider()||!test_ec_point_renames()||!test_hmac_evp_mac()) return 1;
 puts("PASS: all OpenSSL EasyMesh API migration family regressions."); return 0;
}

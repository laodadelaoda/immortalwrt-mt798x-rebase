#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#define C(x) do { if (!(x)) { fprintf(stderr,"FAIL: %s\n",#x); goto out; } } while (0)
int main(void) {
 OSSL_PROVIDER *p=NULL; EVP_MD *md=NULL; EVP_CIPHER *ci=NULL;
 EVP_PKEY_CTX *kg=NULL,*sp=NULL,*vp=NULL; EVP_PKEY *key=NULL;
 EVP_MD_CTX *s=NULL,*v=NULL; EVP_CIPHER_CTX *e=NULL,*d=NULL;
 unsigned char *sig=NULL; size_t sl=0; unsigned char k[16]={0},iv[12]={0},tag[16];
 unsigned char msg[]="N60 OpenSSL 3 Provider regression",ct[128],pt[128];
 int n=0,total=0,tail=0,rc=1; char group[]="prime256v1"; OSSL_PARAM ps[2];
 p=OSSL_PROVIDER_load(NULL,"default"); C(p);
 md=EVP_MD_fetch(NULL,"SHA256","provider=default"); ci=EVP_CIPHER_fetch(NULL,"AES-128-GCM","provider=default"); C(md&&ci);
 kg=EVP_PKEY_CTX_new_from_name(NULL,"EC","provider=default"); C(kg&&EVP_PKEY_keygen_init(kg)>0);
 ps[0]=OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,group,0); ps[1]=OSSL_PARAM_construct_end();
 C(EVP_PKEY_CTX_set_params(kg,ps)>0&&EVP_PKEY_generate(kg,&key)>0);
 s=EVP_MD_CTX_new(); v=EVP_MD_CTX_new();
 C(s&&v&&EVP_DigestSignInit(s,&sp,md,NULL,key)>0&&EVP_DigestSignUpdate(s,msg,sizeof(msg)-1)>0&&EVP_DigestSignFinal(s,NULL,&sl)>0);
 sig=OPENSSL_malloc(sl); C(sig&&EVP_DigestSignFinal(s,sig,&sl)>0);
 C(EVP_DigestVerifyInit(v,&vp,md,NULL,key)>0&&EVP_DigestVerifyUpdate(v,msg,sizeof(msg)-1)>0&&EVP_DigestVerifyFinal(v,sig,sl)==1);
 e=EVP_CIPHER_CTX_new(); d=EVP_CIPHER_CTX_new();
 C(e&&d&&EVP_EncryptInit_ex2(e,ci,k,iv,NULL)>0&&EVP_EncryptUpdate(e,ct,&n,msg,sizeof(msg)-1)>0);
 total=n; C(EVP_EncryptFinal_ex(e,ct+total,&tail)>0&&EVP_CIPHER_CTX_ctrl(e,EVP_CTRL_AEAD_GET_TAG,sizeof(tag),tag)>0); total+=tail;
 C(EVP_DecryptInit_ex2(d,ci,k,iv,NULL)>0&&EVP_DecryptUpdate(d,pt,&n,ct,total)>0&&EVP_CIPHER_CTX_ctrl(d,EVP_CTRL_AEAD_SET_TAG,sizeof(tag),tag)>0&&EVP_DecryptFinal_ex(d,pt+n,&tail)>0);
 C((size_t)(n+tail)==sizeof(msg)-1&&memcmp(pt,msg,sizeof(msg)-1)==0);
 puts("PASS: default Provider SHA256/AES-GCM, P-256 keygen and ECDSA sign/verify."); rc=0;
out:
 OPENSSL_free(sig); EVP_CIPHER_CTX_free(e); EVP_CIPHER_CTX_free(d); EVP_MD_CTX_free(s); EVP_MD_CTX_free(v);
 EVP_PKEY_free(key); EVP_PKEY_CTX_free(kg); EVP_MD_free(md); EVP_CIPHER_free(ci); if(p) OSSL_PROVIDER_unload(p); return rc;
}

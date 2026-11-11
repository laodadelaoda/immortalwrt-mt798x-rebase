#include <stdio.h>
#include <string.h>

extern int des_encrypt(const unsigned char *clear, const unsigned char *key,
                       unsigned char *cypher);

#define PASS(id) puts("PASS_TEST_ID:" id)

int main(void)
{
    static const unsigned char key[7] = {
        0x12, 0x69, 0x5b, 0xc9, 0xb7, 0xb7, 0xf8
    };
    static const unsigned char plain[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    static const unsigned char expected[8] = {
        0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05
    };
    unsigned char out[8] = {0};

    if (des_encrypt(plain, key, out) != 0 ||
        memcmp(out, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "FAIL: internal DES 7-byte key known-answer test\n");
        return 1;
    }

    PASS("des_7byte_key_expansion_internal_backend_known_answer");
    return 0;
}

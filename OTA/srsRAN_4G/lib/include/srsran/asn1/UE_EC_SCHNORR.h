
//Header Files
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>
#include "srsran/asn1/crypto_utils.h"

namespace asn1{
namespace rrc_nr{



// #define MSG_LEN 79
#define CURVE NID_secp224k1

extern std::string basepath;

// void print_hex(const char *label, const unsigned char *buf, size_t len);

unsigned char *read_hex_file_ec_schnorr(const char *filename, size_t *len);

BIGNUM *read_bn_line_ec_schnorr(FILE *file);

EC_KEY *load_pubkey_ec_schnorr(const char *filename);

int schnorr_verify(EC_KEY *verifier, const unsigned char *msg, size_t msg_len, BIGNUM *r, BIGNUM *s);

int run_ec_schnorr_ue();

}
}
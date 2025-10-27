
//Header Files
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "srsran/asn1/rrc_nr/crypto_utils.h"

namespace asn1{
namespace rrc_nr{


#define CURVE NID_secp224k1
#define OPENSSL_API_COMPAT 0x10100000L

extern std::string ec_schnorr_basepath;

// void print_hex(const char *label, const unsigned char *buf, size_t len);

void write_file(const char *filename, const unsigned char *data, size_t len);

unsigned char *serialize_pubkey(EC_KEY *key, size_t *len);

unsigned char *serialize_privkey(EC_KEY *key, size_t *len);

void schnorr_sign_pubkey(EC_KEY *signer, const unsigned char *pub_bytes, size_t len, BIGNUM **r_out, BIGNUM **s_out);

int run_ec_schnorr_amf();

}
}
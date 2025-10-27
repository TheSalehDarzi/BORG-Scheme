// 
// 
/**************************************
 *          EC-Schnorr Algorithm            *
 **************************************
 *
 *Compile:          gcc BS.c -o BS -lcrypto -lssl
 * 
 *Run:              ./BS
 *
 *Documentation:    OpenSSL Library
 *
 * Created By:      << Saleh Darzi >>
_______________________________________________________________________________*/


//Header Files
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>
#include "srsran/asn1/rrc_nr/AMF_EC_SCHNORR.h"
#include "srsran/asn1/rrc_nr/crypto_utils.h"

namespace asn1{
namespace rrc_nr{


#define CURVE NID_secp224k1

// void print_hex(const char *label, const unsigned char *buf, size_t len);

// double get_time_ns();

unsigned char *read_hex_file_ec_schnorr(const char *filename, size_t *len);\

EC_KEY *load_privkey_ec_schnorr(const char *filename);

void schnorr_sign_msg(EC_KEY *key, const unsigned char *msg, size_t msg_len, BIGNUM **r_out, BIGNUM **s_out);

int run_ec_schnorr_bs();


}
}
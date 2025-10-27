// 
// 
/**************************************
 *          ECDSA Algorithm            *
 **************************************
 *
 *Compile:          gcc AMF.c -o AMF -lcrypto -lssl
 * 
 *Run:              ./AMF
 *
 *Documentation:    OpenSSL Library
 *
 * Created By:      << Saleh Darzi >>
_______________________________________________________________________________*/


//Header Files
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>


#include "srsran/asn1/rrc_nr/crypto_utils.h"

namespace asn1 {
namespace rrc_nr {

extern std::string ecdsa_basepath;

#define ECDSA_CURVE_NAME NID_secp224k1

// double get_time_ns();

void write_to_file_ecdsa(const char *filename, const unsigned char *data, size_t len) ;

// void print_hex(const char *label, const unsigned char *data, size_t len);

unsigned char *serialize_pubkey_ecdsa(EVP_PKEY *pkey, size_t *len);

unsigned char *serialize_privkey_ecdsa(EVP_PKEY *pkey, size_t *len);

EVP_PKEY *generate_keypair_ecdsa();

unsigned char *sign_ecdsa(EVP_PKEY *signer, const unsigned char *data, size_t len, size_t *sig_len);

int run_ecdsa_amf();

}
}
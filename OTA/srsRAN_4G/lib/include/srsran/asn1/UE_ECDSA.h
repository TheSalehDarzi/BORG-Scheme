

// 
// 
/**************************************
 *          ECDSA Algorithm            *
 **************************************
 *
 *Compile:          gcc UE.c -o UE -lcrypto -lssl
 * 
 *Run:              ./UE
 *
 *Documentation:    OpenSSL Library
 *
 * Created By:      << Saleh Darzi >>
_______________________________________________________________________________*/


//Header Files
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>
#include "srsran/asn1/crypto_utils.h"

namespace asn1{
namespace rrc_nr{


// #define MSG_LEN 79
#define MAX_SIG 512


extern std::string ecdsa_basepath;

// double get_time_ns();

unsigned char *read_hex_file_ecdsa(const char *filename, size_t *len);

EVP_PKEY *load_pubkey_ecdsa(const char *filename);

int verify_ecdsa(EVP_PKEY *key, const unsigned char *msg, size_t msglen, unsigned char *sig, size_t siglen);

int run_ecdsa_ue();

}
}
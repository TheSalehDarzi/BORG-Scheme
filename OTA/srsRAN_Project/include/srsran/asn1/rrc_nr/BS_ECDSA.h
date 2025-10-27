// 
// 
/**************************************
 *          ECDSA Algorithm            *
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
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>

#include "srsran/asn1/rrc_nr/AMF_ECDSA.h"

#include "srsran/asn1/rrc_nr/crypto_utils.h"

namespace asn1 {
namespace rrc_nr {

// #define MSG_LEN 79




unsigned char *read_hex_file_ecdsa(const char *filename, size_t *len);

EVP_PKEY *load_privkey_ecdsa(const char *filename);

// void print_hex(const char *label, const unsigned char *data, size_t len);

int run_ecdsa_bs();

}
}

// 
// 
/**************************************************
 *          Schnorr HIBS Algorithm                *
 **************************************************
 *Compile:          gcc BS.c -o BS -lcrypto -lssl
 * 
 *Run:              ./BS
 *
 *Documentation:    OpenSSL Library
 *
 * Created By:      << Saleh Darzi >>
_______________________________________________________________________________*/


//Header Files
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string.h>
#include<string>
#include "srsran/asn1/rrc_nr/AMF_HIBS.h"
#include "srsran/asn1/rrc_nr/crypto_utils.h"


namespace asn1{
namespace rrc_nr{
    
// #define CURVE_NAME 712 // Numeric ID for NID_secp224k1 (ed224 curve)
// #define MAX_HEX_SIZE 512
// #define MSG_LEN 79

// void print_hex(const char *label, const unsigned char *data, size_t len);

void sign_message(unsigned char *message, int message_length, int sign_level, EC_GROUP *curve, EC_POINT *QID_AMF, EC_POINT *QID_BS, 
    BIGNUM *sk_BS, BIGNUM *order, BN_CTX *ctx, unsigned char *hash, BIGNUM **zj, EC_POINT **Rj, BIGNUM **hj, double *accurate_sign_time);


int run_hibs_bs();

}
}
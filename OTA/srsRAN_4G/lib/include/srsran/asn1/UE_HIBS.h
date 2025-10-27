// 
// 
/**************************************************
 *          Schnorr HIBS Algorithm                *
 **************************************************
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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string.h>
#include<string>
#include "srsran/asn1/crypto_utils.h"

namespace asn1{
namespace rrc_nr{


/*************************************************************
				    F u n c t i o n s
**************************************************************/
#define HIBS_CURVE_NAME 712 // Numeric ID for NID_secp224k1 (ed224 curve)
// #define MAX_HEX_SIZE 512
// #define MSG_LEN 79


extern std::string hibs_basepath;

void write_bn_to_file_hibs(const BIGNUM *bn, const char *filename);

void write_point_to_file_hibs(const EC_GROUP *group, const EC_POINT *point, const char *filename, BN_CTX *ctx);

BIGNUM *read_bn_from_file_hibs(const char *filename);

EC_POINT *read_point_from_file_hibs(const char *filename, const EC_GROUP *curve, BN_CTX *ctx);

void verify_signature(unsigned char *message, int message_length, EC_GROUP *curve, EC_POINT *MPK, EC_POINT *QID_AMF, EC_POINT *QID_BS, BIGNUM *zj, EC_POINT *Rj, BIGNUM *order, BN_CTX *ctx, double *timing_verif);

int run_hibs_ue();


}
}
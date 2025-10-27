// 
// 
/**************************************************
 *          Schnorr HIBS Algorithm                *
 **************************************************
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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string.h>
#include<string>
#include "srsran/asn1/rrc_nr/crypto_utils.h"


namespace asn1{
namespace rrc_nr{
    

/*************************************************************
				    F u n c t i o n s
**************************************************************/
#define HIBS_CURVE_NAME 712 // Numeric ID for NID_secp224k1 (ed224 curve)
#define MAX_HEX_SIZE 512

extern std::string hibs_basepath;


double get_time_ns();

void print_point(const char *label, const EC_GROUP *curve, const EC_POINT *pt, BN_CTX *ctx);


void print_bn(const char *label, const BIGNUM *bn);

void write_bn_to_file_hibs(const BIGNUM *bn, const char *filename);

void write_point_to_file_hibs(const EC_GROUP *group, const EC_POINT *point, const char *filename, BN_CTX *ctx);

BIGNUM *read_bn_from_file_hibs(const char *filename);

EC_POINT *read_point_from_file_hibs(const char *filename, const EC_GROUP *curve, BN_CTX *ctx);

void system_setup_HIBS(EC_GROUP *curve, EC_POINT **PK0, BIGNUM **sk0, BIGNUM *order, BN_CTX *ctx, unsigned char *hash, double *system_setup_time);


void key_extract_for_AMF_HIBS(const EC_GROUP *curve, const EC_POINT *MPK, const BIGNUM *msk, const BIGNUM *order, BN_CTX *ctx,
    EC_POINT **Q_AMF, BIGNUM **sk_AMF, BIGNUM **h_AMF, double *AMF_KeyExtraction_time);


void key_extract_for_BSs(const EC_GROUP *curve, const EC_POINT *Q_AMF, const BIGNUM *sk_AMF, const BIGNUM *order, BN_CTX *ctx, BIGNUM **sk_BS_root_out, EC_POINT **QID_BS_out, BIGNUM **h_BS, double *BS_KeyExtraction_time);


int run_hibs_amf();

}
}
// 
/********************************************
 *          BORG Algorithm (AMF)            *
 ********************************************
 *Description:      1. (msk, MPK) <--- BORG.Setup()
 *                  2. (sk_AMF, Q_AMF) <--- BORG.KeyExtraction_AMF(msk, MPK, ID_AMF, ID_CKG)
 *                  3. (sk_BS_i, Q_BS) <--- BORG.KeyExtraction_BSs(sk_AMF, Q_AMF, MPK, ID_AMF, ID_BS)
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
#include <string>

#include "srsran/asn1/rrc_nr/crypto_utils.h"

namespace asn1 {
namespace rrc_nr {

#define TBORG_CURVE_NAME 712 // Numeric ID for NID_secp224k1 (ed224 curve)
#define MAX_HEX_SIZE 512

extern std::string tborg_basepath;


// void print_point(const char *label, const EC_GROUP *curve, const EC_POINT *pt, BN_CTX *ctx);



void write_bn_to_file(const BIGNUM *bn, const char *filename);

void write_point_to_file(const EC_GROUP *group, const EC_POINT *point, const char *filename, BN_CTX *ctx);

BIGNUM *read_bn_from_file(const char *filename);

EC_POINT *read_point_from_file(const char *filename, const EC_GROUP *curve, BN_CTX *ctx);

void system_setup(EC_GROUP *curve, EC_POINT **PK0, BIGNUM **sk0, BIGNUM *order, BN_CTX *ctx, unsigned char *hash, double *system_setup_time);

void key_extract_for_AMF(const EC_GROUP *curve, const EC_POINT *MPK, const BIGNUM *msk, const BIGNUM *order, BN_CTX *ctx,
    EC_POINT **Q_AMF, BIGNUM **sk_AMF, BIGNUM **h_AMF, double *AMF_KeyExtraction_time);

void key_extract_for_BSs(const EC_GROUP *curve, const EC_POINT *Q_AMF, const BIGNUM *sk_AMF, const BIGNUM *order, BN_CTX *ctx,
    EC_POINT ***PK_BS_vec, BIGNUM ***sk_BS_vec, BIGNUM **sk_BS_root_out, EC_POINT **QID_BS_out, BIGNUM **h_BS, int *n_out, int *t_out, double *BS_KeyExtraction_time);

void test_BS_reconstruction(const BIGNUM **sk_BS_vec, const int *indices, int t, const BIGNUM *order, BN_CTX *ctx, const BIGNUM *expected_root);


int run_tborg_AMF();

}
}


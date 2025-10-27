

//Header Files
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string>

#include "srsran/asn1/crypto_utils.h"

namespace asn1 {
namespace rrc_nr {
    
    


// void print_point(const char *label, const EC_GROUP *curve, const EC_POINT *pt, BN_CTX *ctx);


void write_bn_to_file(const BIGNUM *bn, const char *filename);

void write_point_to_file(const EC_GROUP *group, const EC_POINT *point, const char *filename, BN_CTX *ctx);

BIGNUM *read_bn_from_file(const char *filename);

EC_POINT *read_point_from_file(const char *filename, const EC_GROUP *curve, BN_CTX *ctx);

int verify_signature(const EC_GROUP *curve, const BIGNUM *order, BN_CTX *ctx, const EC_POINT *g, const EC_POINT *MPK,
    const EC_POINT *Q_AMF, const EC_POINT *QID_BS, const EC_POINT *R_j, const BIGNUM *z_j,
    const unsigned char *ID_AMF, size_t id_amf_len, const unsigned char *ID_BS, size_t id_bs_len,
    const unsigned char *message, size_t message_len, double *Verification_Timing);

int run_tborg_UE();

}
}
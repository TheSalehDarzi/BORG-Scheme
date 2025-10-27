
//Header Files
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string.h>
#include<string>

#include "srsran/asn1/rrc_nr/AMF_T_BORG.h"
#include "srsran/asn1/rrc_nr/crypto_utils.h"


namespace asn1 {
namespace rrc_nr {
    

void compute_R_ij_vector(const EC_GROUP *curve, BN_CTX *ctx, EC_POINT **E_vec, EC_POINT **D_vec,
    BIGNUM **rho_ij_vec, const int *indices, int beta, int j, int J, EC_POINT **R_ij_vec_out  // [beta] long
);


void sign_single_BS(const EC_GROUP *curve, const BIGNUM *order, BN_CTX *ctx, int i, int j, const unsigned char *message, size_t message_len,
    const BIGNUM *rho_ij, const BIGNUM *e_ij, const BIGNUM *d_ij, const BIGNUM *sk_i, const int *indices, int beta,
    const EC_POINT *R_j, BIGNUM **h_j_out, BIGNUM **z_ij_out,const EC_POINT *QID_BS, double *time);



int run_tborg_BS();

}
}

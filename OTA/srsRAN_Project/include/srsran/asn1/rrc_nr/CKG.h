// 
/**************************************
 *          Core Key Generator           *
 **************************************
 
 * 
 *
 *Compile:          see CKG.cpp
 * 
 *Run:              ./ckg
 *
 *Documentation:    OpenSSL Library
 *
 * Created By:      << Mirza Masfiqur Rahman >>
_______________________________________________________________________________*/

#pragma once

//#include "Dilithium_with_Certificate/Dilithium.h"
#include "srsran/asn1/rrc_nr/Modulized_HIBFSS_Schnorr2.h"

#include <fstream>
#include <string>
#include <vector>

namespace asn1 {
namespace rrc_nr {

void save_bignum_dp(BIGNUM** bignumPtr, const std::string& filename);

BIGNUM** load_bignum_dp(const std::string& filename);

void save_bignum_array_nullable(BIGNUM** bn_array, size_t count, const std::string& filename);

BIGNUM** load_bignum_array_nullable(const std::string& filename);

void save_bignum_sp(BIGNUM* bn, const std::string& filename);

BIGNUM* load_bignum_sp(const std::string& filename);

void save_ec_point_dp(EC_GROUP* group, EC_POINT** pointPtr, const std::string& filename, BN_CTX* ctx);

EC_POINT** load_ec_point_dp(EC_GROUP* group, const std::string& filename, BN_CTX* ctx);

void save_ec_point_sp(EC_GROUP* group, EC_POINT* point, const std::string& filename, BN_CTX* ctx);

EC_POINT* load_ec_point_sp(EC_GROUP* group, const std::string& filename, BN_CTX* ctx);

void save_unsigned_char_array(const unsigned char* data, size_t len, const std::string& filename);

unsigned char* load_unsigned_char_array(size_t& len_out, const std::string& filename);

void save_ec_point_array(EC_GROUP* group, EC_POINT** points, size_t count, const std::string& filename, BN_CTX* ctx);

EC_POINT** load_ec_point_array(EC_GROUP* group, const std::string& filename, BN_CTX* ctx);

int generate_primitives_hibfss();

int do_sign_hibfss(unsigned char* message, int message_length);

int do_verify_hibfss(unsigned char* message, int message_length);


}
}

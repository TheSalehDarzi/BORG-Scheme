
//Header Files
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string.h>

namespace asn1{
namespace rrc_nr{

#define MSG_LEN 79  // Random message length


void print_bn(const char *label, const BIGNUM *bn);
/*============================================
   Function to measure time in nanoseconds
=============================================*/
double get_time_ns();

void print_point(const char *label, const EC_GROUP *curve, const EC_POINT *pt, BN_CTX *ctx);

void print_hex(const char *label, const unsigned char *buf, size_t len);

}
}
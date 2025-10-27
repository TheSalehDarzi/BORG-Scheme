
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

#define MAX_HEX_SIZE 512
#define MSG_LEN 79

void print_bn(const char *label, const BIGNUM *bn);
/*============================================
   Function to measure time in nanoseconds
=============================================*/
double get_time_ns();

// /*======================================
//    Utility function to print EC_POINT
// ========================================*/
void print_point(const char *label, const EC_GROUP *curve, const EC_POINT *pt, BN_CTX *ctx);



void print_hex(const char *label, const unsigned char *data, size_t len);

}
}
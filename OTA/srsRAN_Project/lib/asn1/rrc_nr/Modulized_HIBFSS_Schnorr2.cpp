// 
// 
/**************************************
 *          HIBFSS Algorithm            *
 **************************************
 *Description:      1. HIBFSS.Setup()
 *                  2. HIBFSS.KeyExtract()
 *                  3. HIBFSS.Sign()
 *                  4. HIBFSS.MVerify()
 * 
 *
 *Compile:          gcc Modulized_HIBFSS_Schnorr.c -o Modulized_HIBFSS_Schnorr -lcrypto -lssl
 * 
 *Run:              ./Modulized_HIBFSS_Schnorr
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
//#include <linux/time.h>


#include "srsran/asn1/rrc_nr/Modulized_HIBFSS_Schnorr2.h"

namespace asn1 {
namespace rrc_nr {

/*************************************************************
				    F u n c t i o n s
**************************************************************/
#define CURVE_NAME 713 // Numeric ID for NID_secp224r1 (ed224 curve)


/*======================================
   System Setup Algorithm Function
========================================*/
void system_setup(EC_GROUP *curve, EC_POINT **PK0, BIGNUM **sk, BIGNUM *order, BN_CTX *ctx, unsigned char *hash) {
    BIGNUM *alpha = BN_new();
    *sk = BN_new();
    if (!BN_rand_range(alpha, order)) {
        fprintf(stderr, "Error generating alpha\n");
        exit(EXIT_FAILURE);
    }

    print_bn("Alpha0", alpha);
    
    // sk0 = H1(alpha0) (using SHA256 as H1)
    unsigned char alpha_bin[BN_num_bytes(alpha)];
    BN_bn2bin(alpha, alpha_bin);
    SHA256(alpha_bin, BN_num_bytes(alpha), hash);

    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *sk);
    print_bn("sk0", *sk);

    // PK0 = g^sk mod p
    *PK0 = EC_POINT_new(curve);
    if (!EC_POINT_mul(curve, *PK0, *sk, NULL, NULL, ctx)) {
        fprintf(stderr, "Error computing PK0\n");
        exit(EXIT_FAILURE);
    }

    char *pk0_hex = EC_POINT_point2hex(curve, *PK0, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("PK0: %s\n", pk0_hex);
    OPENSSL_free(pk0_hex);

    BN_free(alpha);
}


/*======================================
        Key Extraction Function
========================================*/ 
void key_extract(int k, EC_GROUP *curve, EC_POINT *PK0, BIGNUM *sk, BIGNUM *order, BN_CTX *ctx, EC_POINT ***vec_QIDk, BIGNUM ***vec_hIDk, BIGNUM ***vec_skIDk, unsigned char *hash) {
    // Allocate memory for key storage
    *vec_QIDk = (EC_POINT **)malloc((k + 1) * sizeof(EC_POINT *));
    *vec_hIDk = (BIGNUM **)malloc((k + 1) * sizeof(BIGNUM *));
    *vec_skIDk = (BIGNUM **)malloc((k + 1) * sizeof(BIGNUM *));
    
    (*vec_QIDk)[0] = EC_POINT_dup(PK0, curve);
    (*vec_hIDk)[0] = NULL;
    (*vec_skIDk)[0] = BN_dup(sk);

    BIGNUM *current_sk = BN_dup(sk);
    for (int i = 1; i <= k; i++) {
        printf("\nKey extraction for level %d:\n", i);
        
        double level_start_time = get_time_ns();
        
        BIGNUM *alpha_k = BN_new();
        BN_rand_range(alpha_k, order);
        print_bn("Alpha_k", alpha_k);

        BIGNUM *rk = BN_new();
        unsigned char alpha_k_bin[BN_num_bytes(alpha_k)];
        BN_bn2bin(alpha_k, alpha_k_bin);
        SHA256(alpha_k_bin, BN_num_bytes(alpha_k), hash);
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, rk);
        print_bn("rk", rk);

        // Compute QIDk = g^rk mod p
        (*vec_QIDk)[i] = EC_POINT_new(curve);
        EC_POINT_mul(curve, (*vec_QIDk)[i], rk, NULL, NULL, ctx);

        // Compute hIDk = H1(IDk || vec_QIDk)
        BIGNUM *hIDk = BN_new();
        SHA256((unsigned char *)&i, sizeof(i), hash);
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, hIDk);
        (*vec_hIDk)[i] = hIDk;
        print_bn("hIDk", hIDk);

        // Compute skIDk = current_sk * hIDk + rk mod q
        BIGNUM *skIDk = BN_new();
        BN_mod_mul(skIDk, current_sk, hIDk, order, ctx);
        BN_mod_add(skIDk, skIDk, rk, order, ctx);
        (*vec_skIDk)[i] = skIDk;
        print_bn("skIDk", skIDk);

        BN_copy(current_sk, skIDk);

        double level_end_time = get_time_ns();
        double elapsed_time_level = (level_end_time - level_start_time) / 1e9;  // Convert ns to seconds
        printf("Key extraction for level %d took: %.9f seconds\n", i, elapsed_time_level);

        BN_free(alpha_k);
        BN_free(rk);
    }
    BN_free(current_sk);
}





/*======================================
            Signing Function
========================================*/ 
void sign_message(unsigned char *message, int message_length, int sign_level, EC_GROUP *curve, EC_POINT **vec_QIDk, BIGNUM **vec_skIDk, BIGNUM *order, BN_CTX *ctx, unsigned char *hash, BIGNUM **zj, EC_POINT **Rj, BIGNUM **hj) {
    //printf("Signing message: %s\n", message);

    BIGNUM *rj_hat = BN_new();
    BN_rand_range(rj_hat, order);
    char IDk[9];
    snprintf(IDk, sizeof(IDk), "UserID_%d", sign_level);
    unsigned char rj_data[BN_num_bytes(rj_hat) + sizeof(int) + strlen(IDk)];
    BN_bn2bin(rj_hat, rj_data);
    int level = sign_level;
    memcpy(rj_data + BN_num_bytes(rj_hat), &level, sizeof(int));
    memcpy(rj_data + BN_num_bytes(rj_hat) + sizeof(int), IDk, strlen(IDk));
    SHA256(rj_data, sizeof(rj_data), hash);

    BIGNUM *rj = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, rj);

    *Rj = EC_POINT_new(curve);
    if (!EC_POINT_mul(curve, *Rj, rj, NULL, NULL, ctx)) {
        fprintf(stderr, "Error computing R_j\n");
        // return EXIT_FAILURE;
    }
    print_bn("rj", rj);
    char *Rj_hex = EC_POINT_point2hex(curve, *Rj, POINT_CONVERSION_UNCOMPRESSED, ctx);
    //printf("Rj: %s\n", Rj_hex);
    OPENSSL_free(Rj_hex);

    // Validate vec_QIDk[sign_level] before use
    if (vec_QIDk[sign_level] == NULL) {
        fprintf(stderr, "Error: vec_QIDk[%d] is NULL\n", sign_level);
        // return EXIT_FAILURE;
    }


    // Step 4: Compute hash h_j = H2(Rj || QIDk || message)
    // unsigned char message[] = "Test Message";
    unsigned char combined_data[2048] = {0};
    size_t offset = 0;
    offset += EC_POINT_point2oct(curve, *Rj, POINT_CONVERSION_UNCOMPRESSED, combined_data + offset, 2048 - offset, ctx);
    offset += EC_POINT_point2oct(curve, vec_QIDk[sign_level], POINT_CONVERSION_UNCOMPRESSED, combined_data + offset, 2048 - offset, ctx);
    memcpy(combined_data + offset, message, message_length);
    SHA256(combined_data, offset + message_length, hash);

    *hj = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *hj);
    //print_bn("hj", *hj);
    
    // Step 5: Compute zj = rj + skIDk * hj mod q
    *zj = BN_new();
    if(vec_skIDk[sign_level]==NULL)printf("Null?\n");
    BN_mod_mul(*zj, vec_skIDk[sign_level], *hj, order, ctx);
    BN_mod_add(*zj, rj, *zj, order, ctx);
    print_bn("zj", *zj);
        
    BN_free(rj_hat);
    BN_free(rj);
}

/*======================================
            Verification Function
========================================*/ 
void verify_signature(unsigned char *message, int message_length, int sign_level, EC_GROUP *curve, EC_POINT **vec_QIDk, BIGNUM **vec_hIDk, EC_POINT *PK0, unsigned char *hash, BIGNUM *zj, EC_POINT *Rj, BIGNUM *order, BN_CTX *ctx) {
    // Step 1: Retrieve hID_1 to hID_sign_level
    // printf("Retrieved hIDk values:\n");
    // for (int i = 1; i <= sign_level; i++) {
    //     printf("k=%d ", i);
    //     print_bn("Retrieved hIDk", vec_hIDk[i]);
    // }

    // Step 2: Compute hierarchical Q structure (Q_combined)
    EC_POINT *Q_combined = EC_POINT_new(curve);
    EC_POINT_copy(Q_combined, vec_QIDk[sign_level]);

    BIGNUM *hIDk_accumulator = BN_new();
    BN_copy(hIDk_accumulator, vec_hIDk[sign_level]);

    for (int i = sign_level - 1; i >= 1; i--) {
        EC_POINT *Q_power = EC_POINT_new(curve);
        EC_POINT_mul(curve, Q_power, NULL, vec_QIDk[i], hIDk_accumulator, ctx);
        EC_POINT_add(curve, Q_combined, Q_combined, Q_power, ctx);
        BN_mod_mul(hIDk_accumulator, hIDk_accumulator, vec_hIDk[i], order, ctx);
        EC_POINT_free(Q_power);
    }


    // Step 3: Compute MPK^{hID_1 * hID_2 * ... * hID_sign_level}
    // Step 4: Multiply MPK term into Q_combined
    EC_POINT *MPK_hIDk = EC_POINT_new(curve);
    EC_POINT_mul(curve, MPK_hIDk, NULL, PK0, hIDk_accumulator, ctx);
    EC_POINT_add(curve, Q_combined, Q_combined, MPK_hIDk, ctx);


    // Step 4: Compute hash h_j = H2(Rj || QIDk || message)
    // unsigned char message[] = "Test Message";
    unsigned char combined_data[2048] = {0};
    size_t offset = 0;
    offset += EC_POINT_point2oct(curve, Rj, POINT_CONVERSION_UNCOMPRESSED, combined_data + offset, 2048 - offset, ctx);
    offset += EC_POINT_point2oct(curve, vec_QIDk[sign_level], POINT_CONVERSION_UNCOMPRESSED, combined_data + offset, 2048 - offset, ctx);
    memcpy(combined_data + offset, message, message_length);
    SHA256(combined_data, offset + message_length, hash);

    BIGNUM *hj = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, hj);
    //print_bn("hj", hj);

    // Step 5: Compute (Q_combined)^{h_j}
    EC_POINT *Q_combined_hj = EC_POINT_new(curve);
    EC_POINT_mul(curve, Q_combined_hj, NULL, Q_combined, hj, ctx);

    // Step 6: Compute RHS = Rj * (Q_combined_hj)    
    EC_POINT *RHS = EC_POINT_new(curve);
    EC_POINT_add(curve, RHS, Rj, Q_combined_hj, ctx);

    // Step 7: Compute LHS = g^zj (expected challenge response)
    EC_POINT *LHS = EC_POINT_new(curve);
    EC_POINT_mul(curve, LHS, zj, NULL, NULL, ctx);

    // Step 8: Verification check: LHS == RHS?
    if (EC_POINT_cmp(curve, LHS, RHS, ctx) == 0) {
        printf("\n✔ Signature is VALID! ✅\n");
    } else {
        printf("\n❌ Signature is INVALID! ❌\n");
    }

    EC_POINT_free(Q_combined);
    EC_POINT_free(Q_combined_hj);
    EC_POINT_free(MPK_hIDk);
    EC_POINT_free(RHS);
    EC_POINT_free(LHS);
    BN_free(hIDk_accumulator);
}



/*************************************************************
			            M A I N
**************************************************************/
// int main() {
//     // Initialize OpenSSL objects
//     EC_GROUP *curve = NULL;
//     BIGNUM *alpha = NULL, *sk = NULL, *order = NULL;
//     BIGNUM *rk = NULL, *hIDk = NULL, *skIDk = NULL, *rj = NULL, *zj = NULL;
//     EC_POINT *g = NULL, *QIDk = NULL, *Rj = NULL;
//     BN_CTX *ctx = NULL;


//     // Create a new BN_CTX
//     ctx = BN_CTX_new();
//     if (!ctx) {
//         fprintf(stderr, "Error creating BN_CTX\n");
//         return EXIT_FAILURE;
//     }

//     // Load the curve
//     curve = EC_GROUP_new_by_curve_name(CURVE_NAME);
//     if (!curve) {
//         fprintf(stderr, "Error loading curve\n");
//         BN_CTX_free(ctx);
//         return EXIT_FAILURE;
//     }

//     // Get the generator point and order of the curve
//     g = (EC_POINT *)EC_GROUP_get0_generator(curve);
//     order = BN_new();
//     if (!EC_GROUP_get_order(curve, order, ctx)) {
//         fprintf(stderr, "Error getting curve order\n");
//         EC_GROUP_free(curve);
//         BN_CTX_free(ctx);
//         return EXIT_FAILURE;
//     }



// //====================================== System Setup Algorithm ======================================    
//     double setup_start_time = get_time_ns();

//     EC_POINT *PK0 = NULL;
//     unsigned char hash[SHA256_DIGEST_LENGTH];

//     system_setup(curve, &PK0, &sk, order, ctx, hash);

//     double setup_end_time = get_time_ns();

//     double elapsed_time_setup = (setup_end_time - setup_start_time) / 1e9;  // Convert ns to seconds
//     printf("System Setup phase took: %.9f seconds\n", elapsed_time_setup);




// //====================================== Key Extraction Algorithm ======================================
//     printf("\n==================== KeyExtract Algorithm ====================\n");
//     int k;
//     printf("Enter the Hierarchical Level k: ");
//     scanf("%d", &k);

//     EC_POINT **vec_QIDk;
//     BIGNUM **vec_hIDk;
//     BIGNUM **vec_skIDk;
//     key_extract(k, curve, PK0, sk, order, ctx, &vec_QIDk, &vec_hIDk, &vec_skIDk, hash);




// //====================================== Signing Algorithm ==========================================
// printf("\n==================== Signing Algorithm ====================\n");
//     printf("Enter the level k to sign with: ");
//     int sign_level;
//     scanf("%d", &sign_level);
//     if (sign_level > k || sign_level < 1) {
//         fprintf(stderr, "Invalid level for signing.\n");
//         return EXIT_FAILURE;
//     }

//     unsigned char message[] = "Test Message";
//     int message_length = strlen((char *)message);

//     double sign_start_time = get_time_ns();
    
//     BIGNUM *hj = NULL;
//     sign_message(message, message_length, sign_level, curve, vec_QIDk, vec_skIDk, order, ctx, hash, &zj, &Rj, &hj);

//     double sign_end_time = get_time_ns();

//     double elapsed_time_sign = (sign_end_time - sign_start_time) / 1e9;  // Convert ns to seconds
//     printf("Message Signing phase took: %.9f seconds\n", elapsed_time_sign);



// //====================================== Verification Algorithm ======================================
// printf("\n==================== Verification Algorithm ====================\n");

//     // Ensure sign_level is within bounds
//     if (sign_level < 1 || sign_level > k) {
//         fprintf(stderr, "Error: Invalid sign_level for verification.\n");
//         return EXIT_FAILURE;
//     }

//     double verify_start_time = get_time_ns();

//     verify_signature(sign_level, curve, vec_QIDk, vec_hIDk, PK0, hj, zj, Rj, order, ctx);

//     double verify_end_time = get_time_ns();

//     double elapsed_time_verify = (verify_end_time - verify_start_time) / 1e9;  // Convert ns to seconds
//     printf("Verification phase took: %.9f seconds\n", elapsed_time_verify);


// // Cleanup
//     BN_free(rj);
//     BN_free(zj);
//     BN_free(hj);
//     EC_POINT_free(Rj);
    
//     return EXIT_SUCCESS;   
// }

}
}
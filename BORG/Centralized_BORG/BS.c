// 
// 
/**************************************************
 *          Centralized BORG Algorithm            *
 **************************************************
 *
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



/*************************************************************
				    F u n c t i o n s
**************************************************************/
#define CURVE_NAME 712 // Numeric ID for NID_secp224k1 (ed224 curve)
#define MAX_HEX_SIZE 512
#define MSG_LEN 79

/*============================================
   Function to measure time in nanoseconds
=============================================*/
double get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;  // Convert to nanoseconds
}

/*======================================
   Utility function to print EC_POINT
========================================*/
void print_point(const char *label, const EC_GROUP *curve, const EC_POINT *pt, BN_CTX *ctx) {
    char *hex = EC_POINT_point2hex(curve, pt, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}


/*======================================
   Utility function to print BIGNUMs     
========================================*/
void print_bn(const char *label, const BIGNUM *bn) {
    char *hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}


/*======================================================
        Function to Read & Write in to/from a File
========================================================*/

/*======================================
   Utility function to Read BN to hex file     
========================================*/
void write_bn_to_file(const BIGNUM *bn, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) { perror("File open failed"); exit(EXIT_FAILURE); }

    char *hex = BN_bn2hex(bn);
    fprintf(fp, "%s\n", hex);
    OPENSSL_free(hex);
    fclose(fp);
}

/*======================================
   Utility function to Write EC_POINT to hex file     
========================================*/
void write_point_to_file(const EC_GROUP *group, const EC_POINT *point, const char *filename, BN_CTX *ctx) {
    FILE *fp = fopen(filename, "w");
    if (!fp) { perror("File open failed"); exit(EXIT_FAILURE); }

    char *hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx);
    fprintf(fp, "%s\n", hex);
    OPENSSL_free(hex);
    fclose(fp);
}

/*===============================================
   Utility function to Read bn from hex file     
=================================================*/
BIGNUM *read_bn_from_file(const char *filename) {
    printf("[read_bn] Reading: %s\n", filename);
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror(filename); exit(EXIT_FAILURE); }
    char hex[MAX_HEX_SIZE];
    fgets(hex, sizeof(hex), fp);
    fclose(fp);
    BIGNUM *bn = NULL;
    BN_hex2bn(&bn, hex);
    return bn;
}

/*===================================================
   Utility function to Read EC_POINT from hex file     
=====================================================*/
EC_POINT *read_point_from_file(const char *filename, const EC_GROUP *curve, BN_CTX *ctx) {
    printf("[read_point] Reading: %s\n", filename);
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("Failed to open EC_POINT file"); exit(EXIT_FAILURE); }

    char hex[MAX_HEX_SIZE * 2];
    if (!fgets(hex, sizeof(hex), fp)) {
        perror("Failed to read line from point file");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    // Remove trailing newline if present
    size_t len = strlen(hex);
    if (hex[len - 1] == '\n') {
        hex[len - 1] = '\0';
    }

    EC_POINT *pt = EC_POINT_new(curve);
    if (!EC_POINT_hex2point(curve, hex, pt, ctx)) {
        fprintf(stderr, "Failed to parse EC_POINT from hex in %s\n", filename);
        EC_POINT_free(pt);
        exit(EXIT_FAILURE);
    }

    return pt;
}    

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s:\n", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (len % 32 != 0) printf("\n");
    printf("----------------------------------------\n");
}



/*======================================
            Signing Function
========================================*/ 
void sign_message(unsigned char *message, int message_length, int sign_level, EC_GROUP *curve, EC_POINT *QID_AMF, EC_POINT *QID_BS, 
    BIGNUM *sk_BS, BIGNUM *order, BN_CTX *ctx, unsigned char *hash, BIGNUM **zj, EC_POINT **Rj, BIGNUM **hj, double *accurate_sign_time) {
    printf("Signing message: %s\n", message);
    
    double start_sign_time = get_time_ns();
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
    double end_sign_time = get_time_ns();
    double elapsed_sign_time = (end_sign_time - start_sign_time) / 1e9;

    print_bn("rj", rj);
    char *Rj_hex = EC_POINT_point2hex(curve, *Rj, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("Rj: %s\n", Rj_hex);
    OPENSSL_free(Rj_hex);

    if (QID_AMF == NULL) {
        fprintf(stderr, "Error: QID_AMF is NULL\n");
        // return EXIT_FAILURE;
    }
    if (QID_BS == NULL) {
        fprintf(stderr, "Error: QID_BS is NULL\n");
        // return EXIT_FAILURE;
    }


    // Step 4: Compute hash h_j = H2(Rj || QIDk || message)
    // unsigned char message[] = "Test Message";
    double start_sign_time2 = get_time_ns();
    unsigned char combined_data[2048] = {0};
    size_t offset = 0;
    offset += EC_POINT_point2oct(curve, *Rj, POINT_CONVERSION_UNCOMPRESSED, combined_data + offset, 2048 - offset, ctx);
    offset += EC_POINT_point2oct(curve, QID_BS, POINT_CONVERSION_UNCOMPRESSED, combined_data + offset, 2048 - offset, ctx);
    memcpy(combined_data + offset, message, message_length);
    SHA256(combined_data, offset + message_length, hash);

    *hj = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *hj);
    
    // Step 5: Compute zj = rj + skIDk * hj mod q
    *zj = BN_new();
    BN_mod_mul(*zj, sk_BS, *hj, order, ctx);
    BN_mod_add(*zj, rj, *zj, order, ctx);
    double end_sign_time2 = get_time_ns();
    double elapsed_sign_time2 = (end_sign_time2 - start_sign_time2) / 1e9;
    double final_sign_time = elapsed_sign_time + elapsed_sign_time2;
    *accurate_sign_time = final_sign_time;

    print_bn("hj", *hj);
    print_bn("zj", *zj);
        
    BN_free(rj_hat);
    BN_free(rj);
}


/*************************************************************
                        M A I N
**************************************************************/
int main() {
    int RUNS;
    double total_signing_zij_time = 0.0;
    printf("Enter number of runs: ");
    scanf("%d", &RUNS);

    for (int timing = 0; timing < RUNS; timing++) {
    printf("\n========= RUN #%d =========\n", timing + 1);
    
    //========================================= Initialize OpenSSL objects ===================================================
        // Initialize OpenSSL objects
        BN_CTX *ctx = NULL;
        EC_GROUP *curve = NULL;
        BIGNUM *order = NULL;
        EC_POINT *g = NULL;


        // Create a new BN_CTX
        ctx = BN_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Error creating BN_CTX\n");
            return EXIT_FAILURE;
        }

        // Load the curve
        curve = EC_GROUP_new_by_curve_name(CURVE_NAME);
        if (!curve) {
            fprintf(stderr, "Error loading curve\n");
            BN_CTX_free(ctx);
            return EXIT_FAILURE;
        }

        // Get the generator point and order of the curve
        g = (EC_POINT *)EC_GROUP_get0_generator(curve);
        order = BN_new();
        if (!EC_GROUP_get_order(curve, order, ctx)) {
            fprintf(stderr, "Error getting curve order\n");
            EC_GROUP_free(curve);
            BN_CTX_free(ctx);
            return EXIT_FAILURE;
        }

    //====================================== Signing Algorithm ==========================================
        printf("\n==================== Signing Algorithm ====================\n\n\n");        

        // Read message
        unsigned char message[MSG_LEN];
        FILE *fmsg = fopen("message.txt", "rb");
        if (!fmsg) {
            fprintf(stderr, "message.txt not found!\n");
            return 1;
        }
        if (fread(message, 1, MSG_LEN, fmsg) != MSG_LEN) {
            fprintf(stderr, "message.txt must be exactly %d bytes.\n", MSG_LEN);
            fclose(fmsg);
            return 1;
        }
        fclose(fmsg);
        print_hex("Message", message, MSG_LEN);

        // Read sk_BS
        BIGNUM *sk_BS = read_bn_from_file("sk_BS.txt");
        print_bn("sk_BS", sk_BS);

        // Read Q_AMF
        EC_POINT *Q_AMF = read_point_from_file("Q_AMF.txt", curve, ctx);
        print_point("Q_AMF", curve, Q_AMF, ctx);

        // Read Q_BS
        EC_POINT *QID_BS = read_point_from_file("Q_BS.txt", curve, ctx);
        if (!EC_POINT_is_on_curve(curve, Q_AMF, ctx)) {
            fprintf(stderr, "\u274c Q_AMF is not on the curve!\n");
            exit(EXIT_FAILURE);
        }
        print_point("Q_BS", curve, QID_BS, ctx);

        BIGNUM *hj = NULL;
        int sign_level = 2;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        BIGNUM *zj = NULL;
        EC_POINT *Rj = NULL;
        double sign_start_time = 0.0;
        sign_message(message, MSG_LEN, sign_level, curve, Q_AMF, QID_BS, sk_BS, order, ctx, hash, &zj, &Rj, &hj, &sign_start_time);
        total_signing_zij_time += sign_start_time;
        write_bn_to_file(zj, "z_j.txt");
        write_point_to_file(curve, Rj, "R_j.txt", ctx);

    // ========================================= Cleanup Part ====================================================
        BN_free(order);
        BN_CTX_free(ctx);
        EC_GROUP_free(curve);
    
    }
        // Print average times
    printf("\n====== AVERAGE RESULTS over %d runs ======\n", RUNS);
    printf("Avg. one BS Signing z_ij Time    : %.9f seconds\n", total_signing_zij_time / RUNS);
    printf("==========================================\n");

    return EXIT_SUCCESS;
}

// 
// 
/**************************************************
 *          Centralized BORG Algorithm            *
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
            Verification Function
========================================*/ 
void verify_signature(unsigned char *message, int message_length, EC_GROUP *curve, EC_POINT *MPK, EC_POINT *QID_AMF, EC_POINT *QID_BS, BIGNUM *zj, EC_POINT *Rj, BIGNUM *order, BN_CTX *ctx, double *timing_verif) {
    printf("Signing message: %s\n", message);
    
    double verify_start_time = get_time_ns();
// Compute hID1 = H1(ID_AMF || MPK || Q_AMF)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char *mpk_hex = EC_POINT_point2hex(curve, MPK, POINT_CONVERSION_UNCOMPRESSED, ctx);
    char *qamf_hex = EC_POINT_point2hex(curve, QID_AMF, POINT_CONVERSION_UNCOMPRESSED, ctx);

    // Use a fixed ID of 7 bytes
    const char *ID_AMF = "AMF-001";
    size_t id_len = strlen(ID_AMF);
    size_t concat_len = id_len + strlen(mpk_hex) + strlen(qamf_hex);
    unsigned char *concat = malloc(concat_len + 1);
    snprintf((char *)concat, concat_len + 1, "%s%s%s", ID_AMF, mpk_hex, qamf_hex);

    // Step 5: Compute hID1 
    SHA256(concat, strlen((char *)concat), hash);

    BIGNUM *h_AMF = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, h_AMF);
    double verify_end_time = get_time_ns();
    double elapsed1 = (verify_end_time - verify_start_time) / 1e9;
    print_bn("h_AMF", h_AMF);


// h_BS = H1(ID_BS || Q_AMF || QID_BS)
    double verify_start_time2 = get_time_ns();
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    double H1_BS_start_time = get_time_ns();
    const char *ID_BS = "BS-000001";
    char *qamf_hex2 = EC_POINT_point2hex(curve, QID_AMF, POINT_CONVERSION_UNCOMPRESSED, ctx);
    char *qbs_hex = EC_POINT_point2hex(curve, QID_BS, POINT_CONVERSION_UNCOMPRESSED, ctx);

    size_t concat_len2 = strlen(ID_BS) + strlen(qamf_hex2) + strlen(qbs_hex);
    unsigned char *concat2 = malloc(concat_len2 + 1);
    snprintf((char *)concat2, concat_len2 + 1, "%s%s%s", ID_BS, qamf_hex2, qbs_hex);

    BIGNUM *h_BS = BN_new();
    SHA256(concat2, strlen((char *)concat2), hash2);
    double H1_BS_end_time = get_time_ns();
    double elapsed_time_H1_BS = (H1_BS_end_time - H1_BS_start_time) / 1e9;  // Convert ns to seconds
    
    BN_bin2bn(hash2, SHA256_DIGEST_LENGTH, h_BS);
    double verify_end_time2 = get_time_ns();
    double elapsed2 = (verify_end_time2 - verify_start_time2) / 1e9;
    print_bn("h_BS", h_BS);
    // write_bn_to_file(*h_BS, "h_BS.txt");

// Compute hash h_j = H2(Rj || QIDk || message)
    double verify_start_time3 = get_time_ns();
    unsigned char combined_data[2048] = {0};
    size_t offset = 0;
    offset += EC_POINT_point2oct(curve, Rj, POINT_CONVERSION_UNCOMPRESSED, combined_data + offset, 2048 - offset, ctx);
    offset += EC_POINT_point2oct(curve, QID_BS, POINT_CONVERSION_UNCOMPRESSED, combined_data + offset, 2048 - offset, ctx);
    memcpy(combined_data + offset, message, message_length);
    SHA256(combined_data, offset + message_length, hash);

    BIGNUM *hj = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, hj);
    double verify_end_time3 = get_time_ns();
    double elapsed3 = (verify_end_time3 - verify_start_time3) / 1e9;
    print_bn("hj", hj);
    


    double verify_start_time4 = get_time_ns();
    // Step 2: Compute hierarchical Q structure (Q_combined)
    EC_POINT *Q_combined = EC_POINT_new(curve);
    EC_POINT_copy(Q_combined, QID_BS);

    BIGNUM *hIDk_accumulator = BN_new();
    BN_copy(hIDk_accumulator, h_BS);
    
    EC_POINT *Q_power = EC_POINT_new(curve);
    EC_POINT_mul(curve, Q_power, NULL, QID_AMF, hIDk_accumulator, ctx);
    EC_POINT_add(curve, Q_combined, Q_combined, Q_power, ctx);
    BN_mod_mul(hIDk_accumulator, hIDk_accumulator, h_AMF, order, ctx);
    EC_POINT_free(Q_power);




    // Step 3: Compute MPK^{hID_1 * hID_2 * ... * hID_sign_level}
    // Step 4: Multiply MPK term into Q_combined
    EC_POINT *MPK_hIDk = EC_POINT_new(curve);
    EC_POINT_mul(curve, MPK_hIDk, NULL, MPK, hIDk_accumulator, ctx);
    EC_POINT_add(curve, Q_combined, Q_combined, MPK_hIDk, ctx);

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
    double verify_end_time4 = get_time_ns();
    double elapsed4 = (verify_end_time4 - verify_start_time4) / 1e9;
    double timing_done = elapsed1 + elapsed2 + elapsed3 + elapsed4;
    *timing_verif = timing_done;

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
int main() {
    int RUNS;
    double total_verification_time = 0.0;
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

    //====================================== Verification Algorithm ======================================
    printf("\n==================== Verification Algorithm ====================\n");

    // Ensure sign_level is within bounds
    int sign_level =2;
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

    // Read MPK
    EC_POINT *MPK = read_point_from_file("MPK.txt", curve, ctx);
    print_point("MPK", curve, MPK, ctx);

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

    // Read R_j
    EC_POINT *R_j = read_point_from_file("R_j.txt", curve, ctx);
    print_point("R_j", curve, R_j, ctx);

    // Read z_j
    BIGNUM *z_j = read_bn_from_file("z_j.txt");
    print_bn("z_j", z_j);

    double verify_start_time = 0.0;
    verify_signature(message, MSG_LEN, curve, MPK, Q_AMF, QID_BS, z_j, R_j, order, ctx, &verify_start_time);

    total_verification_time += verify_start_time;

    // ========================================= Cleanup Part ====================================================
        BN_free(order);
        BN_CTX_free(ctx);
        EC_GROUP_free(curve);
        BN_free(z_j);
        EC_POINT_free(R_j);            
    }
        // Print average times
    printf("\n====== AVERAGE RESULTS over %d runs ======\n", RUNS);
    printf("Avg. one Verification Time    : %.9f seconds\n", total_verification_time / RUNS);
    printf("==========================================\n");

    return EXIT_SUCCESS;
}

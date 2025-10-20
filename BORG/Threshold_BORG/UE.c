// 
// 
/**************************************
 *          BORG Algorithm            *
 **************************************
 *Description:      1. {0,1} <--- BORG.MVerify(m_j, ID_AMF, ID_BS, MPK, Q_AMF, QBS, R_j, z_j)
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
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

/*************************************************************
				    F u n c t i o n s
**************************************************************/
#define CURVE_NAME 712 // Numeric ID for NID_secp224r1 (ed224 curve)
#define MAX_HEX_SIZE 512


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


/*======================================
            Verification Function
========================================*/ 
int verify_signature(const EC_GROUP *curve, const BIGNUM *order, BN_CTX *ctx, const EC_POINT *g, const EC_POINT *MPK,
    const EC_POINT *Q_AMF, const EC_POINT *QID_BS, const EC_POINT *R_j, const BIGNUM *z_j,
    const unsigned char *ID_AMF, size_t id_amf_len, const unsigned char *ID_BS, size_t id_bs_len,
    const unsigned char *message, size_t message_len, double *Verification_Timing
) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    double inside_verifying_start_time = get_time_ns();
    // === Step 1: h_AMF = H1(ID_AMF || MPK || Q_AMF) ===
    char *mpk_hex = EC_POINT_point2hex(curve, MPK, POINT_CONVERSION_UNCOMPRESSED, ctx);
    char *qamf_hex = EC_POINT_point2hex(curve, Q_AMF, POINT_CONVERSION_UNCOMPRESSED, ctx);
    unsigned char *h_amf_input = malloc(id_amf_len + strlen(mpk_hex) + strlen(qamf_hex));
    memcpy(h_amf_input, ID_AMF, id_amf_len);
    memcpy(h_amf_input + id_amf_len, mpk_hex, strlen(mpk_hex));
    memcpy(h_amf_input + id_amf_len + strlen(mpk_hex), qamf_hex, strlen(qamf_hex));
    SHA256(h_amf_input, id_amf_len + strlen(mpk_hex) + strlen(qamf_hex), hash);
    BIGNUM *h_amf = BN_new(); BN_bin2bn(hash, SHA256_DIGEST_LENGTH, h_amf);
    free(h_amf_input); OPENSSL_free(mpk_hex); OPENSSL_free(qamf_hex);

    // === Step 2: h_BS = H1(ID_BS || Q_AMF || QID_BS) ===
    char *qamf_hex2 = EC_POINT_point2hex(curve, Q_AMF, POINT_CONVERSION_UNCOMPRESSED, ctx);
    char *qid_hex2 = EC_POINT_point2hex(curve, QID_BS, POINT_CONVERSION_UNCOMPRESSED, ctx);
    unsigned char *h_bs_input = malloc(id_bs_len + strlen(qamf_hex2) + strlen(qid_hex2));
    memcpy(h_bs_input, ID_BS, id_bs_len);
    memcpy(h_bs_input + id_bs_len, qamf_hex2, strlen(qamf_hex2));
    memcpy(h_bs_input + id_bs_len + strlen(qamf_hex2), qid_hex2, strlen(qid_hex2));
    SHA256(h_bs_input, id_bs_len + strlen(qamf_hex2) + strlen(qid_hex2), hash);
    BIGNUM *h_bs = BN_new(); BN_bin2bn(hash, SHA256_DIGEST_LENGTH, h_bs);
    free(h_bs_input); OPENSSL_free(qamf_hex2); OPENSSL_free(qid_hex2);

    // === Step 3: h_j = H(R_j || QID_BS || message) ===
    char *rj_hex = EC_POINT_point2hex(curve, R_j, POINT_CONVERSION_UNCOMPRESSED, ctx);
    char *qid_hex3 = EC_POINT_point2hex(curve, QID_BS, POINT_CONVERSION_UNCOMPRESSED, ctx);
    size_t h_input_len = strlen(rj_hex) + strlen(qid_hex3) + message_len;
    unsigned char *h_input = malloc(h_input_len);
    memcpy(h_input, rj_hex, strlen(rj_hex));
    memcpy(h_input + strlen(rj_hex), qid_hex3, strlen(qid_hex3));
    memcpy(h_input + strlen(rj_hex) + strlen(qid_hex3), message, message_len);
    SHA256(h_input, h_input_len, hash);
    BIGNUM *h_j = BN_new(); BN_bin2bn(hash, SHA256_DIGEST_LENGTH, h_j);
    free(h_input); OPENSSL_free(rj_hex); OPENSSL_free(qid_hex3);
    
    double inside_verifying_end_time = get_time_ns();
    double elapsed_time_inside_verifying = (inside_verifying_end_time - inside_verifying_start_time) / 1e9;  // Convert ns to seconds

    // === Step 4: Debug info ===
    printf("\n[Verification Detailed Computational Info]\n");
    print_bn("h_AMF", h_amf);
    print_bn("h_BS", h_bs);
    print_bn("h_j", h_j);
    printf("Q_BS: %s\n", EC_POINT_point2hex(curve, QID_BS, POINT_CONVERSION_UNCOMPRESSED, ctx));
    printf("Q_AMF: %s\n", EC_POINT_point2hex(curve, Q_AMF, POINT_CONVERSION_UNCOMPRESSED, ctx));
    printf("MPK: %s\n", EC_POINT_point2hex(curve, MPK, POINT_CONVERSION_UNCOMPRESSED, ctx));

    // === Step 5: Compute inner = QID_BS + Q_AMF^{h_BS} + MPK^{h_AMF * h_BS} ===
    double inside_verifying_start_time2 = get_time_ns();

    BIGNUM *hamf_hbs = BN_new();
    BN_mod_mul(hamf_hbs, h_amf, h_bs, order, ctx);

    EC_POINT *qamf_hbs = EC_POINT_new(curve);
    EC_POINT_mul(curve, qamf_hbs, NULL, Q_AMF, h_bs, ctx);

    EC_POINT *mpk_h = EC_POINT_new(curve);
    EC_POINT_mul(curve, mpk_h, NULL, MPK, hamf_hbs, ctx);

    EC_POINT *inner = EC_POINT_new(curve);
    EC_POINT_copy(inner, QID_BS);
    EC_POINT_add(curve, inner, inner, qamf_hbs, ctx);
    EC_POINT_add(curve, inner, inner, mpk_h, ctx);

    char *inner_hex = EC_POINT_point2hex(curve, inner, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("INNER (QID_BS + Q_AMF^h_BS + MPK^{h_AMF * h_BS}): %s\n", inner_hex);
    OPENSSL_free(inner_hex);

    // === Step 6: Compute RHS = R_j + inner^h_j ===
    EC_POINT *inner_hj = EC_POINT_new(curve);
    EC_POINT_mul(curve, inner_hj, NULL, inner, h_j, ctx);

    EC_POINT *rhs = EC_POINT_new(curve);
    EC_POINT_copy(rhs, R_j);
    EC_POINT_add(curve, rhs, rhs, inner_hj, ctx);

    // char *g_hex = EC_POINT_point2hex(curve, g, POINT_CONVERSION_UNCOMPRESSED, ctx);
    // printf("Generator g: %s\n", g_hex);
    // OPENSSL_free(g_hex);

    // === Step 7: Compute LHS = g^z_j ===
    EC_POINT *lhs = EC_POINT_new(curve);
    // EC_POINT_mul(curve, lhs, NULL, g, z_j, ctx);  // ✅ Correct LHS = g^z_j
    EC_POINT_mul(curve, lhs, z_j, NULL, NULL, ctx);

    char *lhs_hex = EC_POINT_point2hex(curve, lhs, POINT_CONVERSION_UNCOMPRESSED, ctx);
    char *rhs_hex = EC_POINT_point2hex(curve, rhs, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("\nLHS (g^z_j): %s\n", lhs_hex);
    printf("RHS (R_j + inner^h_j): %s\n", rhs_hex);
    OPENSSL_free(lhs_hex); OPENSSL_free(rhs_hex);

    int result = EC_POINT_cmp(curve, lhs, rhs, ctx);
    
    double inside_verifying_end_time2 = get_time_ns();
    double elapsed_time_inside_verifying2 = (inside_verifying_end_time2 - inside_verifying_start_time2) / 1e9;  // Convert ns to seconds
    double UE_Verifying_time = elapsed_time_inside_verifying2 + elapsed_time_inside_verifying;
    printf("\n UE_Verifying_time: %.9f seconds\n\n", UE_Verifying_time);
    *Verification_Timing = UE_Verifying_time;

    // === Cleanup ===
    BN_free(h_amf); BN_free(h_bs); BN_free(h_j); BN_free(hamf_hbs);
    EC_POINT_free(qamf_hbs); EC_POINT_free(mpk_h);
    EC_POINT_free(inner); EC_POINT_free(inner_hj);
    EC_POINT_free(rhs); EC_POINT_free(lhs);

    return result == 0;
}


/*************************************************************
                        M A I N
**************************************************************/
int main() {

    int RUNS;
    double total_Verification_Timing = 0.0;
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

    //========================================= Load everything from files ===================================================
        EC_POINT *MPK = read_point_from_file("MPK.txt", curve, ctx);
        EC_POINT *Q_AMF = read_point_from_file("Q_AMF.txt", curve, ctx);
        EC_POINT *QID_BS = read_point_from_file("Q_BS.txt", curve, ctx);
        EC_POINT *R_j = read_point_from_file("R_j.txt", curve, ctx);
        BIGNUM *z_j = read_bn_from_file("z_j.txt");
        
        // Message and IDs (hardcoded)
        unsigned char message[38] = "This is a 38-byte message for signing!";
        size_t message_len = strlen((char *)message);
        const unsigned char ID_AMF[7] = "AMF-001";
        const unsigned char ID_BS[9] = "BS-000001";

        printf("\n==================== Verifying Signature =====================\n");

        double Verification_Timing;
        int valid = verify_signature(
            curve, order, ctx,
            g, MPK,
            Q_AMF, QID_BS,
            R_j, z_j,
            ID_AMF, sizeof(ID_AMF),
            ID_BS, sizeof(ID_BS),
            message, sizeof(message), &Verification_Timing
        );
        total_Verification_Timing += Verification_Timing;

        if (valid) {
            printf("\n \u2705 Signature verification SUCCESS. ✅ \n");
        } else {
            printf("\n \u274C Signature verification FAILED. ❌ \n");
        }

        // Clean up
        EC_POINT_free(MPK);
        EC_POINT_free(Q_AMF);
        EC_POINT_free(QID_BS);
        EC_POINT_free(R_j);
        BN_free(z_j);
        BN_free(order);
        BN_CTX_free(ctx);
    }
    // Print average times
    printf("\n====== AVERAGE RESULTS over %d runs ======\n", RUNS);
    printf("Avg. Verification Time     : %.9f seconds\n", total_Verification_Timing / RUNS);
    printf("==========================================\n");

    return EXIT_SUCCESS;
}
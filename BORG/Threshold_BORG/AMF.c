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



/*************************************************************
				    F u n c t i o n s
**************************************************************/
#define CURVE_NAME 712 // Numeric ID for NID_secp224k1 (ed224 curve)
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
   System Setup Algorithm Function
========================================*/
void system_setup(EC_GROUP *curve, EC_POINT **PK0, BIGNUM **sk0, BIGNUM *order, BN_CTX *ctx, unsigned char *hash, double *system_setup_time) {
    BIGNUM *alpha = BN_new();
    *sk0 = BN_new();
    double get_alpha0_start_time = get_time_ns();
    if (!BN_rand_range(alpha, order)) {
        fprintf(stderr, "Error generating alpha\n");
        exit(EXIT_FAILURE);
    }
    double get_alpha0_end_time = get_time_ns();
    double elapsed_time_get_alpha0 = (get_alpha0_end_time - get_alpha0_start_time) / 1e9;  // Convert ns to seconds
    printf("elapsed_time_get_alpha0: %.9f seconds\n", elapsed_time_get_alpha0);

    print_bn("Alpha_CKG", alpha);
    
    // sk0 = H1(alpha0) (using SHA256 as H1)
    unsigned char alpha_bin[BN_num_bytes(alpha)];
    BN_bn2bin(alpha, alpha_bin);
    
    double hashing_alpha0_start_time = get_time_ns();
    SHA256(alpha_bin, BN_num_bytes(alpha), hash);
    double hashing_alpha0_end_time = get_time_ns();
    double elapsed_time_hashing_alpha0 = (hashing_alpha0_end_time - hashing_alpha0_start_time) / 1e9;  // Convert ns to seconds
    printf("elapsed_time_hashing_alpha0: %.9f seconds\n", elapsed_time_hashing_alpha0);

    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *sk0);
    print_bn("msk", *sk0);
    write_bn_to_file(*sk0, "msk.txt");

    // PK0 = g^sk mod p
    *PK0 = EC_POINT_new(curve);
    double compute_MPK_start_time = get_time_ns();
    if (!EC_POINT_mul(curve, *PK0, *sk0, NULL, NULL, ctx)) {
        fprintf(stderr, "Error computing PK0\n");
        exit(EXIT_FAILURE);
    }
    double compute_MPK_end_time = get_time_ns();
    double elapsed_time_compute_MPK = (compute_MPK_end_time - compute_MPK_start_time) / 1e9;  // Convert ns to seconds
    printf("elapsed_time_compute_MPK: %.9f seconds\n", elapsed_time_compute_MPK);

    double system_setup_time2 = elapsed_time_get_alpha0 + elapsed_time_hashing_alpha0+ elapsed_time_compute_MPK;
    printf("\n system_setup_time: %.9f seconds\n\n", system_setup_time2);
    * system_setup_time = system_setup_time2;


    char *pk0_hex = EC_POINT_point2hex(curve, *PK0, POINT_CONVERSION_UNCOMPRESSED, ctx);
    printf("MPK: %s\n", pk0_hex);
    write_point_to_file(curve, *PK0, "MPK.txt", ctx);
    OPENSSL_free(pk0_hex);

    BN_free(alpha);
}


/*======================================
        Key Extraction Function (AMF)
========================================*/ 
void key_extract_for_AMF(const EC_GROUP *curve, const EC_POINT *MPK, const BIGNUM *msk, const BIGNUM *order, BN_CTX *ctx,
    EC_POINT **Q_AMF, BIGNUM **sk_AMF, BIGNUM **h_AMF, double *AMF_KeyExtraction_time) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Step 1: Sample alpha1 ∈ Z_q
    BIGNUM *alpha1 = BN_new();
    double get_alpha1_start_time = get_time_ns();
    BN_rand_range(alpha1, order);
    double get_alpha1_end_time = get_time_ns();
    double elapsed_time_get_alpha1 = (get_alpha1_end_time - get_alpha1_start_time) / 1e9;  // Convert ns to seconds


    // Step 2: Compute r = H1(alpha1)
    BIGNUM *r1 = BN_new();
    unsigned char alpha_bin[BN_num_bytes(alpha1)];
    BN_bn2bin(alpha1, alpha_bin);

    double hash_alpha1_start_time = get_time_ns();
    SHA256(alpha_bin, BN_num_bytes(alpha1), hash);
    double hash_alpha1_end_time = get_time_ns();
    double elapsed_time_hash_alpha1 = (hash_alpha1_end_time - hash_alpha1_start_time) / 1e9;  // Convert ns to seconds

    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, r1);

    // Step 3: Compute Q_AMF = g^r
    *Q_AMF = EC_POINT_new(curve);
    double compute_Q_AMF_start_time = get_time_ns();
    EC_POINT_mul(curve, *Q_AMF, r1, NULL, NULL, ctx);
    double compute_Q_AMF_end_time = get_time_ns();
    double elapsed_time_compute_Q_AMF = (compute_Q_AMF_end_time - compute_Q_AMF_start_time) / 1e9;  // Convert ns to seconds

    // Step 4: Concatenate MPK || Q_AMF
    char *mpk_hex = EC_POINT_point2hex(curve, MPK, POINT_CONVERSION_UNCOMPRESSED, ctx);
    char *qamf_hex = EC_POINT_point2hex(curve, *Q_AMF, POINT_CONVERSION_UNCOMPRESSED, ctx);

    // Use a fixed ID of 7 bytes
    double hID1_start_time = get_time_ns();
    const char *ID_AMF = "AMF-001";
    size_t id_len = strlen(ID_AMF);
    size_t concat_len = id_len + strlen(mpk_hex) + strlen(qamf_hex);
    unsigned char *concat = malloc(concat_len + 1);
    snprintf((char *)concat, concat_len + 1, "%s%s%s", ID_AMF, mpk_hex, qamf_hex);

    // Step 5: Compute hID1 = H1(ID_AMF || MPK || Q_AMF)
    SHA256(concat, strlen((char *)concat), hash);
    double hID1_end_time = get_time_ns();
    double elapsed_time_hID1 = (hID1_end_time - hID1_start_time) / 1e9;  // Convert ns to seconds

    *h_AMF = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *h_AMF);

    // Step 6: Compute sk_AMF = msk * hID1 + r mod order
    double sk_AMF_start_time = get_time_ns();
    *sk_AMF = BN_new();
    BN_mod_mul(*sk_AMF, msk, *h_AMF, order, ctx);
    BN_mod_add(*sk_AMF, *sk_AMF, r1, order, ctx);
    double sk_AMF_end_time = get_time_ns();
    double elapsed_time_sk_AMF = (sk_AMF_end_time - sk_AMF_start_time) / 1e9;  // Convert ns to seconds

    // Optional prints for debug
    print_bn("r1_AMF", r1);
    print_bn("h_AMF (hID1)", *h_AMF);
    print_bn("sk_AMF", *sk_AMF);

    // Writ to file
    // write_bn_to_file(*h_AMF, "h_AMF.txt");
    write_bn_to_file(*sk_AMF, "sk_AMF.txt");
    write_point_to_file(curve, *Q_AMF, "Q_AMF.txt", ctx);

    double AMF_KeyExtraction_time2 = elapsed_time_sk_AMF + elapsed_time_hID1+ elapsed_time_compute_Q_AMF + elapsed_time_hash_alpha1 + elapsed_time_get_alpha1;
    printf("\n AMF_KeyExtraction_time: %.9f seconds\n\n", AMF_KeyExtraction_time2);
    *AMF_KeyExtraction_time = AMF_KeyExtraction_time2;

    // Cleanup
    BN_free(alpha1);
    BN_free(r1);
    OPENSSL_free(mpk_hex);
    OPENSSL_free(qamf_hex);
    free(concat);
} 




/*======================================
        Key Extraction Function (BSs)
========================================*/
void key_extract_for_BSs(const EC_GROUP *curve, const EC_POINT *Q_AMF, const BIGNUM *sk_AMF, const BIGNUM *order, BN_CTX *ctx,
    EC_POINT ***PK_BS_vec, BIGNUM ***sk_BS_vec, BIGNUM **sk_BS_root_out, EC_POINT **QID_BS_out, BIGNUM **h_BS, int *n_out, int *t_out, double *BS_KeyExtraction_time) {

    unsigned char hash[SHA256_DIGEST_LENGTH];

    // printf("Enter number of base stations n = ");
    // scanf("%d", &n);
    // printf("Enter threshold t = ");
    // scanf("%d", &t);

    // if (t > n || t < 1) {
    //     printf("Invalid threshold. Ensure 1 ≤ t ≤ n.\n");
    //     return;
    // }
    int n = 3;
    int t = 2;

    *n_out = n;
    *t_out = t;

    // Step 1: Random alpha_bs and compute r = H1(alpha_bs)
    BIGNUM *alpha_bs = BN_new();
    double get_alpha_BS_start_time = get_time_ns();
    BN_rand_range(alpha_bs, order);
    double get_alpha_BS_end_time = get_time_ns();
    double elapsed_time_get_alpha_BS = (get_alpha_BS_end_time - get_alpha_BS_start_time) / 1e9;  // Convert ns to seconds

    BIGNUM *r2 = BN_new();
    unsigned char alpha_bin[BN_num_bytes(alpha_bs)];
    BN_bn2bin(alpha_bs, alpha_bin);
    double hash_alpha_BS_start_time = get_time_ns();
    SHA256(alpha_bin, BN_num_bytes(alpha_bs), hash);
    double hash_alpha_BS_end_time = get_time_ns();
    double elapsed_time_get_hash_alpha_BS = (hash_alpha_BS_end_time - hash_alpha_BS_start_time) / 1e9;  // Convert ns to seconds
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, r2);
    
    // QID_BS = g^r2
    *QID_BS_out = EC_POINT_new(curve);
    double Q_BS_start_time = get_time_ns();
    EC_POINT_mul(curve, *QID_BS_out, r2, NULL, NULL, ctx);
    double Q_BS_end_time = get_time_ns();
    double elapsed_time_get_Q_BS = (Q_BS_end_time - Q_BS_start_time) / 1e9;  // Convert ns to seconds
    
    write_point_to_file(curve, *QID_BS_out, "Q_BS.txt", ctx);


    // h_BS = H1(ID_BS || Q_AMF || QID_BS)
    double H1_BS_start_time = get_time_ns();
    const char *ID_BS = "BS-000001";
    char *qamf_hex = EC_POINT_point2hex(curve, Q_AMF, POINT_CONVERSION_UNCOMPRESSED, ctx);
    char *qbs_hex = EC_POINT_point2hex(curve, *QID_BS_out, POINT_CONVERSION_UNCOMPRESSED, ctx);

    size_t concat_len = strlen(ID_BS) + strlen(qamf_hex) + strlen(qbs_hex);
    unsigned char *concat = malloc(concat_len + 1);
    snprintf((char *)concat, concat_len + 1, "%s%s%s", ID_BS, qamf_hex, qbs_hex);

    *h_BS = BN_new();
    SHA256(concat, strlen((char *)concat), hash);
    double H1_BS_end_time = get_time_ns();
    double elapsed_time_H1_BS = (H1_BS_end_time - H1_BS_start_time) / 1e9;  // Convert ns to seconds
    
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *h_BS);
    print_bn("h_BS", *h_BS);
    // write_bn_to_file(*h_BS, "h_BS.txt");

    // sk_BS_root = sk_AMF * h_BS + r2
    BIGNUM *sk_BS_root = BN_new();
    double sk_BS_start_time = get_time_ns();
    BN_mod_mul(sk_BS_root, sk_AMF, *h_BS, order, ctx);
    BN_mod_add(sk_BS_root, sk_BS_root, r2, order, ctx);
    double sk_BS_end_time = get_time_ns();
    double elapsed_time_sk_BS = (sk_BS_end_time - sk_BS_start_time) / 1e9;  // Convert ns to seconds
    
    *sk_BS_root_out = BN_dup(sk_BS_root);

    print_bn("sk_BS_root", sk_BS_root);

    // Step 2: Generate secret sharing polynomial
    double Lagrange_start_time = get_time_ns();
    BIGNUM **coeffs = malloc(t * sizeof(BIGNUM *));
    coeffs[0] = BN_dup(sk_BS_root);
    for (int i = 1; i < t; i++) {
        coeffs[i] = BN_new();
        BN_rand_range(coeffs[i], order);
    }
    double Lagrange_end_time = get_time_ns();
    double elapsed_time_Lagrange = (Lagrange_end_time - Lagrange_start_time) / 1e9;  // Convert ns to seconds
    
    // Step 3: Allocate and generate shares
    *sk_BS_vec = malloc(n * sizeof(BIGNUM *));
    *PK_BS_vec = malloc(n * sizeof(EC_POINT *));
    
    double BS_KeyExtraction_time2;

    for (int i = 0; i < n; i++) {
        double Lagrange2_start_time = get_time_ns();
        BIGNUM *x = BN_new();
        BN_set_word(x, i + 1);  // Evaluate at x = 1, 2, ..., n

        BIGNUM *share = BN_new();
        BN_zero(share);
        BIGNUM *power = BN_new();
        BN_one(power);

        for (int j = 0; j < t; j++) {
            BIGNUM *term = BN_new();
            BN_mod_mul(term, coeffs[j], power, order, ctx);
            BN_mod_add(share, share, term, order, ctx);
            BN_mod_mul(power, power, x, order, ctx);
            BN_free(term);
        }

        (*sk_BS_vec)[i] = BN_dup(share);
        (*PK_BS_vec)[i] = EC_POINT_new(curve);
        EC_POINT_mul(curve, (*PK_BS_vec)[i], share, NULL, NULL, ctx);
        double Lagrange2_end_time = get_time_ns();
        BS_KeyExtraction_time2 = BS_KeyExtraction_time2 + ((Lagrange2_end_time - Lagrange2_start_time) / 1e9);  // Convert ns to seconds

        printf("BS %d:\n", i + 1);
        print_bn("sk_BS_i", (*sk_BS_vec)[i]);
        char *pk_hex = EC_POINT_point2hex(curve, (*PK_BS_vec)[i], POINT_CONVERSION_UNCOMPRESSED, ctx);
        printf("PK_BS_%d: %s\n", i + 1, pk_hex);
        OPENSSL_free(pk_hex);

        // Write sk_BS_i to file
        char fname[50];
        snprintf(fname, sizeof(fname), "sk_BS_%d.txt", i + 1);
        write_bn_to_file((*sk_BS_vec)[i], fname);

        BN_free(x);
        BN_free(power);
        BN_free(share);
    }

    BS_KeyExtraction_time2 = elapsed_time_get_alpha_BS + elapsed_time_get_hash_alpha_BS + elapsed_time_get_Q_BS + elapsed_time_H1_BS + elapsed_time_sk_BS + elapsed_time_Lagrange;
    printf("\n BS_KeyExtraction_time: %.9f seconds\n\n", BS_KeyExtraction_time2);
    *BS_KeyExtraction_time = BS_KeyExtraction_time2;

    // Cleanup
    for (int i = 0; i < t; i++) BN_free(coeffs[i]);
    free(coeffs);
    BN_free(alpha_bs);
    BN_free(r2);
    BN_free(sk_BS_root);
    OPENSSL_free(qamf_hex);
    OPENSSL_free(qbs_hex);
    free(concat);
}




/*============================================
        Test Key Extraction Function (BSs)
==============================================*/
void test_BS_reconstruction(const BIGNUM **sk_BS_vec, const int *indices, int t, const BIGNUM *order, BN_CTX *ctx, const BIGNUM *expected_root) {
    BIGNUM *reconstructed = BN_new();
    BN_zero(reconstructed);

    for (int i = 0; i < t; i++) {
        BIGNUM *lambda_i = BN_new();
        BN_one(lambda_i);

        BIGNUM *xi = BN_new();
        BN_set_word(xi, indices[i]);  // xi = x_i (1-based)

        for (int j = 0; j < t; j++) {
            if (i == j) continue;

            BIGNUM *xj = BN_new(); BN_set_word(xj, indices[j]);

            BIGNUM *num = BN_new();  // -xj mod order
            BIGNUM *den = BN_new();  // xi - xj mod order
            BIGNUM *inv = BN_new();
            BIGNUM *temp = BN_new();

            // num = -xj mod order
            BN_mod_sub(num, BN_value_one(), xj, order, ctx);
            BN_mod_sub(num, order, xj, order, ctx);  // safer

            // den = xi - xj mod order
            BN_mod_sub(den, xi, xj, order, ctx);

            // inv = den^-1 mod order
            if (!BN_mod_inverse(inv, den, order, ctx)) {
                fprintf(stderr, "Error: no modular inverse for denominator in Lagrange basis\n");
                exit(EXIT_FAILURE);
            }

            // temp = num * inv mod order
            BN_mod_mul(temp, num, inv, order, ctx);

            // lambda_i *= temp mod order
            BN_mod_mul(lambda_i, lambda_i, temp, order, ctx);

            // Clean up
            BN_free(xj); BN_free(num); BN_free(den); BN_free(inv); BN_free(temp);
        }

        // Debug print λ_i
        printf("λ_%d (Lagrange coeff for x = %d): ", indices[i], indices[i]);
        print_bn("", lambda_i);

        // Multiply λ_i with sk_BS_i
        BIGNUM *term = BN_new();
        BN_mod_mul(term, sk_BS_vec[indices[i] - 1], lambda_i, order, ctx);

        // Add to reconstruction
        BN_mod_add(reconstructed, reconstructed, term, order, ctx);

        BN_free(lambda_i);
        BN_free(xi);
        BN_free(term);
    }

    BN_mod(reconstructed, reconstructed, order, ctx);

    printf("\nReconstructed root secret key from shares:\n");
    print_bn("sk_BS_reconstructed", reconstructed);

    if (BN_cmp(reconstructed, expected_root) == 0) {
        printf("\n✅ Reconstruction SUCCESS: matches original sk_BS_root.\n");
    } else {
        printf("\n❌ Reconstruction FAILED: does not match original sk_BS_root.\n");
    }

    BN_free(reconstructed);
}


/*************************************************************
			            M A I N
**************************************************************/
int main() {
    
    int RUNS;
    double total_system_setup_time = 0.0;
    double total_amf_keyex_time = 0.0;
    double total_bs_keyex_time = 0.0;
    // int runs;
    printf("Enter number of runs: ");
    scanf("%d", &RUNS);

    for (int timing = 0; timing < RUNS; timing++) {
    printf("\n========= RUN #%d =========\n", timing + 1);

        // Initialize OpenSSL objects
        EC_GROUP *curve = NULL;
        BIGNUM *order = NULL;
        EC_POINT *g = NULL;
        BN_CTX *ctx = NULL;

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

    //====================================== System Setup Algorithm ======================================    
        printf("\n==================== System Setup Algorithm for CKG ====================\n");
        BIGNUM *msk = NULL;
        EC_POINT *MPK = NULL;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        
        double system_setup_time;
        system_setup(curve, &MPK, &msk, order, ctx, hash, &system_setup_time);
        total_system_setup_time += system_setup_time;

    //====================================== Key Extraction Algorithm for AMF ======================================
        printf("\n==================== KeyExtract Algorithm for AMF ====================\n");

        EC_POINT *Q_AMF = NULL;
        BIGNUM *sk_AMF = NULL;
        BIGNUM *hID1_AMF = NULL;

        double AMF_KeyExtraction_time;
        key_extract_for_AMF(curve, MPK, msk, order, ctx, &Q_AMF, &sk_AMF, &hID1_AMF, &AMF_KeyExtraction_time);
        total_amf_keyex_time += AMF_KeyExtraction_time;

        // Optional: print Q_AMF as hex
        char *q_amf_hex = EC_POINT_point2hex(curve, Q_AMF, POINT_CONVERSION_UNCOMPRESSED, ctx);
        printf("Q_AMF (g^r): %s\n", q_amf_hex);
        OPENSSL_free(q_amf_hex);
        
    //====================================== Key Extraction Algorithm for BSs ======================================
        printf("\n==================== KeyExtract Algorithm for BSs ====================\n");
        
        EC_POINT **PK_BS_vec;
        BIGNUM **sk_BS_vec;
        BIGNUM *sk_BS_root = NULL;
        EC_POINT *QID_BS = NULL;
        BIGNUM *hID1_BS = NULL;
        int n, t; 
        
        double BS_KeyExtraction_time;
        key_extract_for_BSs(curve, Q_AMF, sk_AMF, order, ctx, &PK_BS_vec, &sk_BS_vec, &sk_BS_root, &QID_BS, &hID1_BS, &n ,&t, &BS_KeyExtraction_time);
        total_bs_keyex_time += BS_KeyExtraction_time;

    // Now QID_BS is accessible outside and can be printed or passed forward
        char *qbs_hex = EC_POINT_point2hex(curve, QID_BS, POINT_CONVERSION_UNCOMPRESSED, ctx);
        printf("QID_BS: %s\n", qbs_hex);
        OPENSSL_free(qbs_hex);

    //  Automatically Fill First t Indices 
        int *indices = malloc(t * sizeof(int));
        for (int i = 0; i < t; i++) {
            indices[i] = i + 1;  // First t BSs (1-based)
        }

        test_BS_reconstruction((const BIGNUM **)sk_BS_vec, indices, t, order, ctx, sk_BS_root);

    // ========================================= Cleanup Part ====================================================

        // ======= Cleanup: BS Keys =======
        for (int i = 0; i < n; i++) {
            if (PK_BS_vec[i]) EC_POINT_free(PK_BS_vec[i]);
            if (sk_BS_vec[i]) BN_free(sk_BS_vec[i]);
        }
        free(PK_BS_vec);
        free(sk_BS_vec);
        free(indices);

        // ======= Cleanup: Secret/Public Key Materials =======
        if (Q_AMF) EC_POINT_free(Q_AMF);
        if (QID_BS) EC_POINT_free(QID_BS);
        if (MPK) EC_POINT_free(MPK);

        if (msk) BN_free(msk);
        if (sk_AMF) BN_free(sk_AMF);
        if (hID1_AMF) BN_free(hID1_AMF);
        if (sk_BS_root) BN_free(sk_BS_root);
        if (hID1_BS) BN_free(hID1_BS);
        if (order) BN_free(order);

        // ======= Cleanup: Curve and Context =======
        if (curve) EC_GROUP_free(curve);
        if (ctx) BN_CTX_free(ctx);

        printf("\n==================== The End ====================\n");
}
    // Print average times
    printf("\n====== AVERAGE RESULTS over %d runs ======\n", RUNS);
    printf("Avg. System Setup Time     : %.9f seconds\n", total_system_setup_time / RUNS);
    printf("Avg. AMF Key Extraction    : %.9f seconds\n", total_amf_keyex_time / RUNS);
    printf("Avg. BS Key Extraction     : %.9f seconds\n", total_bs_keyex_time / RUNS);
    printf("==========================================\n");

    return EXIT_SUCCESS;   
}

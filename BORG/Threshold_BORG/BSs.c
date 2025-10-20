// 
// 
/**************************************
 *          BORG Algorithm            *
 **************************************
 *Description:      1. (E_ij, D_ij) <--- BORG.Preprocess(J)
 *                  2. (R_j, z_j) <--- BORG.Sign(m_j, sk_BS_i) 
 *
 *Compile:          gcc BSs.c -o BSs -lcrypto -lssl
 * 
 *Run:              ./BSs
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
   Utility function to read commitments1
========================================*/
// Read e_ij and d_ij from ed.txt
void read_commitment_scalars(int i, int j, BIGNUM **e_out, BIGNUM **d_out) {
    char e_hex[1024], d_hex[1024];
    int ii, jj;
    FILE *fp = fopen("ed1.txt", "r");
    if (!fp) { perror("ed1.txt open failed"); exit(1); }

    while (fscanf(fp, "%d %d %s %s", &ii, &jj, e_hex, d_hex) == 4) {
        if (ii == i && jj == j) {
            BN_hex2bn(e_out, e_hex);
            BN_hex2bn(d_out, d_hex);
            break;
        }
    }
    fclose(fp);
}

/*======================================
   Utility function to read Commitments2
========================================*/
void read_commitments_from_combined_files(int i, int j,
    BIGNUM **e_ij, BIGNUM **d_ij,
    EC_POINT **E_ij, EC_POINT **D_ij,
    const EC_GROUP *curve, BN_CTX *ctx)
{
    FILE *fp_bn = fopen("ed1.txt", "r");
    if (!fp_bn) { perror("ed1.txt open failed"); exit(EXIT_FAILURE); }

    int ii, jj;
    char e_hex[1024], d_hex[1024];
    while (fscanf(fp_bn, "%d %d %s %s", &ii, &jj, e_hex, d_hex) == 4) {
        if (ii == i && jj == j) {
            BN_hex2bn(e_ij, e_hex);
            BN_hex2bn(d_ij, d_hex);
            break;
        }
    }
    fclose(fp_bn);

    FILE *fp_pt = fopen("ED2.txt", "r");
    if (!fp_pt) { perror("ED2.txt open failed"); exit(EXIT_FAILURE); }

    char E_hex[2048], D_hex[2048];
    while (fscanf(fp_pt, "%d %d %s %s", &ii, &jj, E_hex, D_hex) == 4) {
        if (ii == i && jj == j) {
            *E_ij = EC_POINT_new(curve);
            *D_ij = EC_POINT_new(curve);
            EC_POINT_hex2point(curve, E_hex, *E_ij, ctx);
            EC_POINT_hex2point(curve, D_hex, *D_ij, ctx);
            break;
        }
    }
    fclose(fp_pt);
}


/*======================================
        Preprocessing Function
========================================*/ 
void preprocess_commitments_for_BSs(int n, int J, const EC_GROUP *curve, const BIGNUM *order, EC_POINT *g, BN_CTX *ctx,
    EC_POINT **E_vec, EC_POINT **D_vec, BIGNUM **e_scalars, BIGNUM **d_scalars, double *elapsed_timeeee) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    FILE *fp_bn = fopen("ed1.txt", "w");
    FILE *fp_pt = fopen("ED2.txt", "w");
    if (!fp_bn || !fp_pt) {
    perror("Failed to open output files");
    exit(EXIT_FAILURE);
    }
    double elapsed_time_Preprocess_J = 0.00;

    for (int i = 1; i <= n; i++) {
    char id_bs[10];
    snprintf(id_bs, sizeof(id_bs), "BS-%06d", i); // 9-byte ID_BS_i

    double Preprocess_J_start_time = get_time_ns();
    for (int j = 1; j <= J; j++) {
    int index = (i - 1) * J + (j - 1);  // Flattened index

    // Sample ê and d̂ from Z_q
    BIGNUM *e_hat = BN_new();
    BIGNUM *d_hat = BN_new();
    BN_rand_range(e_hat, order);
    BN_rand_range(d_hat, order);

    // Compute e_{i,j} = H1(e_hat || j || ID_BS_i)
    unsigned char e_input[BN_num_bytes(e_hat) + sizeof(int) + 9];
    int offset = 0;
    offset += BN_bn2bin(e_hat, e_input);
    memcpy(e_input + offset, &j, sizeof(int));
    memcpy(e_input + offset + sizeof(int), id_bs, 9);
    SHA256(e_input, offset + sizeof(int) + 9, hash);
    e_scalars[index] = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, e_scalars[index]);

    // Compute d_{i,j} = H1(d_hat || j || ID_BS_i)
    unsigned char d_input[BN_num_bytes(d_hat) + sizeof(int) + 9];
    offset = 0;
    offset += BN_bn2bin(d_hat, d_input);
    memcpy(d_input + offset, &j, sizeof(int));
    memcpy(d_input + offset + sizeof(int), id_bs, 9);
    SHA256(d_input, offset + sizeof(int) + 9, hash);
    d_scalars[index] = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, d_scalars[index]);

    // Compute E_{i,j} = g^{e_{i,j}}
    E_vec[index] = EC_POINT_new(curve);
    EC_POINT_mul(curve, E_vec[index], e_scalars[index], NULL, NULL, ctx);

    // Compute D_{i,j} = g^{d_{i,j}}
    D_vec[index] = EC_POINT_new(curve);
    EC_POINT_mul(curve, D_vec[index], d_scalars[index], NULL, NULL, ctx);
    
    double Preprocess_J_end_time = get_time_ns();
    elapsed_time_Preprocess_J += (Preprocess_J_end_time - Preprocess_J_start_time) / 1e9;  // Convert ns to seconds

    // Write e_ij, d_ij to ed.txt
    char *e_hex = BN_bn2hex(e_scalars[index]);
    char *d_hex = BN_bn2hex(d_scalars[index]);
    fprintf(fp_bn, "%d %d %s %s\n", i, j, e_hex, d_hex);
    OPENSSL_free(e_hex);
    OPENSSL_free(d_hex);

    // Write E_ij, D_ij to ED.txt
    char *E_hex = EC_POINT_point2hex(curve, E_vec[index], POINT_CONVERSION_UNCOMPRESSED, ctx);
    char *D_hex = EC_POINT_point2hex(curve, D_vec[index], POINT_CONVERSION_UNCOMPRESSED, ctx);
    fprintf(fp_pt, "%d %d %s %s\n", i, j, E_hex, D_hex);
    OPENSSL_free(E_hex);
    OPENSSL_free(D_hex);

    // Clean up
    BN_free(e_hat);
    BN_free(d_hat);
    }
    }
    printf("\n Preprocessing_time: %.9f seconds\n\n", elapsed_time_Preprocess_J);
    *elapsed_timeeee = elapsed_time_Preprocess_J;

    fclose(fp_bn);
    fclose(fp_pt);

    // Ask user if they want to print commitments for a specific j
//     char choice;
//     printf("\nDo you want to display all commitment values for a specific message index j? (y/n): ");
//     scanf(" %c", &choice);

//     if (choice == 'y' || choice == 'Y') {
//     int chosen_j;
//     printf("Enter message index j (1 to %d): ", J);
//     scanf("%d", &chosen_j);

//     if (chosen_j < 1 || chosen_j > J) {
//     printf("Invalid j.\n");
//     return;
//     }

//     printf("\nCommitment values for j = %d:\n", chosen_j);
//     for (int i = 1; i <= n; i++) {
//     int index = (i - 1) * J + (chosen_j - 1);

//     char *E_hex = EC_POINT_point2hex(curve, E_vec[index], POINT_CONVERSION_UNCOMPRESSED, ctx);
//     char *D_hex = EC_POINT_point2hex(curve, D_vec[index], POINT_CONVERSION_UNCOMPRESSED, ctx);

//     printf("BS %d:\n", i);
//     printf("  E[%d][%d] = %s\n", i, chosen_j, E_hex);
//     printf("  D[%d][%d] = %s\n", i, chosen_j, D_hex);
//     print_bn("  e_{i,j}", e_scalars[index]);
//     print_bn("  d_{i,j}", d_scalars[index]);

//     OPENSSL_free(E_hex);
//     OPENSSL_free(D_hex);
//     }
// }
}  


/*======================================
    Function to Compute rho_ij Values
========================================*/
void compute_rho_ij_vector(const EC_GROUP *curve, BN_CTX *ctx, const unsigned char *message, size_t message_len,
    EC_POINT **E_vec, EC_POINT **D_vec, const int *indices, int beta, int j, int J, BIGNUM **rho_ij_vec_out  // [beta] long
) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    for (int i = 0; i < beta; i++) {
        int signer = indices[i];

        // === Estimate hash input length ===
        size_t input_len = sizeof(int) + message_len;
        for (int k = 0; k < beta; k++) {
            int index = (indices[k] - 1) * J + (j - 1);
            char *E_hex = EC_POINT_point2hex(curve, E_vec[index], POINT_CONVERSION_UNCOMPRESSED, ctx);
            char *D_hex = EC_POINT_point2hex(curve, D_vec[index], POINT_CONVERSION_UNCOMPRESSED, ctx);
            input_len += strlen(E_hex) + strlen(D_hex);
            OPENSSL_free(E_hex);
            OPENSSL_free(D_hex);
        }

        unsigned char *input = malloc(input_len);
        int offset = 0;
        memcpy(input + offset, &signer, sizeof(int)); offset += sizeof(int);
        memcpy(input + offset, message, message_len); offset += message_len;

        for (int k = 0; k < beta; k++) {
            int index = (indices[k] - 1) * J + (j - 1);
            char *E_hex = EC_POINT_point2hex(curve, E_vec[index], POINT_CONVERSION_UNCOMPRESSED, ctx);
            char *D_hex = EC_POINT_point2hex(curve, D_vec[index], POINT_CONVERSION_UNCOMPRESSED, ctx);
            memcpy(input + offset, E_hex, strlen(E_hex)); offset += strlen(E_hex);
            memcpy(input + offset, D_hex, strlen(D_hex)); offset += strlen(D_hex);
            OPENSSL_free(E_hex);
            OPENSSL_free(D_hex);
        }

        SHA256(input, input_len, hash);
        rho_ij_vec_out[i] = BN_new();
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, rho_ij_vec_out[i]);
        free(input);
    }
}


/*======================================
  Function to Compute R_ij Values Vector
========================================*/
void compute_R_ij_vector(const EC_GROUP *curve, BN_CTX *ctx, EC_POINT **E_vec, EC_POINT **D_vec,
    BIGNUM **rho_ij_vec, const int *indices, int beta, int j, int J, EC_POINT **R_ij_vec_out  // [beta] long
) {
    for (int i = 0; i < beta; i++) {
        int signer = indices[i];
        int index = (signer - 1) * J + (j - 1);

        R_ij_vec_out[i] = EC_POINT_new(curve);
        EC_POINT *temp = EC_POINT_new(curve);

        // R_ij = D_ij + E_ij^rho_ij
        EC_POINT_copy(R_ij_vec_out[i], D_vec[index]);
        EC_POINT_mul(curve, temp, NULL, E_vec[index], rho_ij_vec[i], ctx);
        EC_POINT_add(curve, R_ij_vec_out[i], R_ij_vec_out[i], temp, ctx);

        EC_POINT_free(temp);
    }
}

/*======================================
         New Single Signing Function
========================================*/
void sign_single_BS(const EC_GROUP *curve, const BIGNUM *order, BN_CTX *ctx, int i, int j, const unsigned char *message, size_t message_len,
    const BIGNUM *rho_ij, const BIGNUM *e_ij, const BIGNUM *d_ij, const BIGNUM *sk_i, const int *indices, int beta,
    const EC_POINT *R_j, BIGNUM **h_j_out, BIGNUM **z_ij_out,const EC_POINT *QID_BS, double *time) 
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    double h_j_start_time = get_time_ns();
    // === Step 1: Compute h_j = H(R_j || QID_BS || message) if not already ===
    if (*h_j_out == NULL) {
        char *rj_hex = EC_POINT_point2hex(curve, R_j, POINT_CONVERSION_UNCOMPRESSED, ctx);
        char *qid_hex = EC_POINT_point2hex(curve, QID_BS, POINT_CONVERSION_UNCOMPRESSED, ctx);
        size_t rj_len = strlen(rj_hex), qid_len = strlen(qid_hex);
        size_t total_len = rj_len + qid_len + message_len;

        unsigned char *h_input = malloc(total_len);
        memcpy(h_input, rj_hex, rj_len);
        memcpy(h_input + rj_len, qid_hex, qid_len);
        memcpy(h_input + rj_len + qid_len, message, message_len);

        SHA256(h_input, total_len, hash);
        *h_j_out = BN_new();
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, *h_j_out);

        OPENSSL_free(rj_hex); OPENSSL_free(qid_hex);
        free(h_input);
    }
    double h_j_end_time = get_time_ns();
    double elapsed_time_h_j = (h_j_end_time - h_j_start_time) / 1e9;  // Convert ns to seconds

    
    BIGNUM *lambda = BN_new();
    BN_one(lambda);

    double Lagrange_start_time = get_time_ns();
    BIGNUM *xi = BN_new();
    BN_set_word(xi, indices[i]);  // Correct x-coordinate (e.g., 1, 2, ...)

    for (int k = 0; k < beta; k++) {
        if (indices[k] == indices[i]) continue;  // skip same x-coordinate

        BIGNUM *xk = BN_new(); BN_set_word(xk, indices[k]);
        BIGNUM *num = BN_new(); BN_sub(num, order, xk);      // -x_k mod order
        BIGNUM *den = BN_new(); BN_mod_sub(den, xi, xk, order, ctx);
        BIGNUM *inv = BN_mod_inverse(NULL, den, order, ctx);
        BIGNUM *temp = BN_new(); BN_mod_mul(temp, num, inv, order, ctx);

        BN_mod_mul(lambda, lambda, temp, order, ctx);

        BN_free(xk); BN_free(num); BN_free(den); BN_free(inv); BN_free(temp);
    }
    double Lagrange_end_time = get_time_ns();
    double elapsed_time_Lagrange = (Lagrange_end_time - Lagrange_start_time) / 1e9;  // Convert ns to seconds

    // Debug print to confirm correct Lagrange coefficient
    printf("λ_%d (Lagrange coeff for x = %d): ", indices[i], indices[i]);
    print_bn("lambda", lambda);

    BN_free(xi);

    // === Step 3: Compute z_ij = d_ij + e_ij*rho + lambda*sk_i*h_j mod order ===
    BIGNUM *term1 = BN_new();
    BIGNUM *term2 = BN_new();
    *z_ij_out = BN_new();

    double z_ij_start_time = get_time_ns();
    BN_mod_mul(term1, e_ij, rho_ij, order, ctx);
    BN_mod_mul(term2, lambda, sk_i, order, ctx);
    BN_mod_mul(term2, term2, *h_j_out, order, ctx);
    BN_mod_add(*z_ij_out, d_ij, term1, order, ctx);
    BN_mod_add(*z_ij_out, *z_ij_out, term2, order, ctx);
    double z_ij_end_time = get_time_ns();
    double elapsed_time_z_ij = (z_ij_end_time - z_ij_start_time) / 1e9;  // Convert ns to seconds

    double BS_Signing_time = elapsed_time_z_ij + elapsed_time_Lagrange + elapsed_time_h_j;
    printf("\n BS_Signing_zij_time: %.9f seconds\n\n", BS_Signing_time);
    *time = BS_Signing_time;

    // Cleanup
    BN_free(lambda);
    BN_free(term1);
    BN_free(term2);
}

/*************************************************************
                        M A I N
**************************************************************/
int main() {
    int RUNS;
    double total_Preprocessing_time = 0.0;
    double total_signing_zij_time = 0.0;
    double total_aggregation_time = 0.0;
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

    //=========================================== Getting  n & t ================================================
        int n=3, t=2;
        // printf("Enter number of signers n: ");
        // scanf("%d", &n);
        // printf("Enter threshold t: ");
        // scanf("%d", &t);

    //====================================== Preprocessing Algorithm ==========================================
        printf("\n==================== Preprocessing Algorithm ====================\n");
        int J=1;
        // printf("Enter number of messages to be signed J = ");
        // scanf("%d", &J);

        // Allocate space for flattened commitment vectors
        // Commitment data vectors
        EC_POINT **E_vec = malloc(n * J * sizeof(EC_POINT *));
        EC_POINT **D_vec = malloc(n * J * sizeof(EC_POINT *));
        BIGNUM **e_scalars = malloc(n * J * sizeof(BIGNUM *));
        BIGNUM **d_scalars = malloc(n * J * sizeof(BIGNUM *));

        // Call the preprocessing function
        double preprocessing_timing;
        preprocess_commitments_for_BSs(n, J, curve, order, g, ctx, E_vec, D_vec, e_scalars, d_scalars, &preprocessing_timing);
        total_Preprocessing_time += preprocessing_timing;

    //====================================== Signing Algorithm ==========================================
        printf("\n==================== Signing Algorithm ====================\n\n\n");
        
        int i = 1, j=1;

        

        double BS_Full_Sign_time;

        while (i <= t) {
        printf("\n\n++++++++++++++++++++ BS_%d is signing +++++++++++++++++++++++++ \n\n", i);

        // Read sk_BS_i
        char fname[100];
        snprintf(fname, sizeof(fname), "sk_BS_%d.txt", i);
        // printf("Trying to read: %s\n", fname);
        BIGNUM *sk_i = read_bn_from_file(fname);
        printf("for BS%d\n", i);
        print_bn("sk_i", sk_i);

        // Read Q_AMF and QID_BS
        EC_POINT *Q_AMF = read_point_from_file("Q_AMF.txt", curve, ctx);
        print_point("Q_AMF", curve, Q_AMF, ctx);

        EC_POINT *QID_BS = read_point_from_file("Q_BS.txt", curve, ctx);
        if (!EC_POINT_is_on_curve(curve, Q_AMF, ctx)) {
            fprintf(stderr, "\u274c Q_AMF is not on the curve!\n");
            exit(EXIT_FAILURE);
        }
        print_point("Q_BS", curve, QID_BS, ctx);

        EC_POINT *R_j = EC_POINT_new(curve);
        EC_POINT_set_to_infinity(curve, R_j);

        // Build index array [1,2,...,t]
        int *indices = malloc(t * sizeof(int));
        for (int x = 0; x < t; x++) indices[x] = x + 1;

        // Message to be signed
        unsigned char message[38] = "This is a 38-byte message for signing!";
        size_t message_len = strlen((char *)message);

        for (int bs = 1; bs <= n; bs++) {
            for (int msg = 1; msg <= J; msg++) {
                int idx = (bs - 1) * J + (msg - 1);
                read_commitments_from_combined_files(bs, msg,
                    &e_scalars[idx], &d_scalars[idx],
                    &E_vec[idx], &D_vec[idx],
                    curve, ctx);
            }
        }
        
        double rho_R_Aggregate_ij_start_time = get_time_ns();
        // === Step 2: Compute rho_ij vector ===
        int beta = t;
        BIGNUM **rho_ij_vec = malloc(beta * sizeof(BIGNUM *));
        compute_rho_ij_vector(curve, ctx, message, message_len,
            E_vec, D_vec, indices, beta, j, J, rho_ij_vec);

        // === Step 3: Compute R_ij vector ===
        EC_POINT **R_ij_vec = malloc(beta * sizeof(EC_POINT *));
        compute_R_ij_vector(curve, ctx, E_vec, D_vec,
            rho_ij_vec, indices, beta, j, J, R_ij_vec);

        // === Step 4: Aggregate R_j ===
        for (int ix = 0; ix < beta; ix++) {
            EC_POINT_add(curve, R_j, R_j, R_ij_vec[ix], ctx);
        }
        double rho_R_Aggregate_ij_end_time = get_time_ns();
        double elapsed_time_rho_R_Aggregate_ij = (rho_R_Aggregate_ij_end_time - rho_R_Aggregate_ij_start_time) / 1e9;  // Convert ns to seconds

        print_point("R_j", curve, R_j, ctx);
        write_point_to_file(curve, R_j, "R_j.txt", ctx);

        // === Step 5: Locate current signer index ===
        int my_index = -1;
        for (int k = 0; k < beta; k++) {
            if (indices[k] == i) {
                my_index = k;
                break;
            }
        }
        if (my_index == -1) {
            printf("\u274c Error: i not found in indices[]\n");
            exit(EXIT_FAILURE);
        }

        // === Step 6: Call signing function ===
        int flat_index = (i - 1) * J + (j - 1);
        BIGNUM *z_ij = NULL;
        BIGNUM *h_j = NULL;
        // double z_ij_time[t+1];

        double *z_ij_time = malloc(t * sizeof(double));
        
        sign_single_BS(
            curve, order, ctx,
            my_index, j,
            message, message_len,
            rho_ij_vec[my_index],
            e_scalars[flat_index], d_scalars[flat_index],
            sk_i, indices, beta,
            R_j, &h_j, &z_ij,
            QID_BS, &z_ij_time[i-1]);

        printf("\n\u2705 Final output for BS_%d, j = %d\n", i, j);
        print_bn("z_{i,j}", z_ij);
        
        double Each_BS_Signing_time = z_ij_time[i-1] + elapsed_time_rho_R_Aggregate_ij;
        printf("\n BS_%d_Full_Signing_time: %.9f seconds\n\n", i, Each_BS_Signing_time);
        total_signing_zij_time += Each_BS_Signing_time;

        // Write z_ij to file
        char z_fname[100];
        snprintf(z_fname, sizeof(z_fname), "z_BS_%d_j.txt", i);
        write_bn_to_file(z_ij, z_fname);

        i++;
        }

        printf("\n==================== Aggregation ====================\n");
        BIGNUM *z_j = BN_new();
        BN_zero(z_j);

        double aggregation_time;

        for (int count = 1; count <= t; count++) {
            // Read z_BS_i
            char z_fname[100];
            snprintf(z_fname, sizeof(z_fname), "z_BS_%d_j.txt", count);
            // printf("Trying to read: %s\n", z_fname);
            BIGNUM *z_ij = read_bn_from_file(z_fname);
            print_bn("z_ij", z_ij);
            double aggregate_start_time = get_time_ns();
            BN_mod_add(z_j, z_j, z_ij, order, ctx);
            double aggregate_end_time = get_time_ns();
            aggregation_time = aggregation_time + ((aggregate_end_time - aggregate_start_time) / 1e9);  // Convert ns to seconds

            BN_free(z_ij);
        }

        printf("\n✅ Aggregated z_j: ");
        print_bn("z_j", z_j);

        printf("\n aggregation_time: %.9f seconds\n\n", aggregation_time);
        total_aggregation_time += aggregation_time;

        // Now write z_j to file or send to verifier
        write_bn_to_file(z_j, "z_j.txt");

        // Cleanup
        BN_free(z_j);

    // ========================================= Cleanup Part ====================================================
        // Cleanup (truncated for brevity)
        // BN_free(z_ij);
        // BN_free(h_j);
        // EC_POINT_free(R_j);
        // EC_POINT_free(QID_BS);
        BN_free(order);
        BN_CTX_free(ctx);
        EC_GROUP_free(curve);
    }
    // Print average times
    printf("\n====== AVERAGE RESULTS over %d runs ======\n", RUNS);
    printf("Avg. Preprocessing for J=1 Time     : %.9f seconds\n", total_Preprocessing_time / RUNS);
    printf("Avg. one BS Signing z_ij Time    : %.9f seconds\n", total_signing_zij_time / RUNS);
    printf("Avg. Aggregation Time     : %.9f seconds\n", total_aggregation_time / RUNS);
    printf("==========================================\n");

    return EXIT_SUCCESS;
}

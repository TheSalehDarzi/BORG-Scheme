/*******************************************************************
 *          Dilithium with 2-level Certificate Algorithm            *
 *******************************************************************
 *
 *Description:      1. Generate key pairs for 3 entities: Global CA, CKG, BS
 *                  2. Create the certificates by signing the public keys
 *                  3. BS signs a random message
 *                  4. UE verifies the message and the chain of certificates
 *                  5. Write all the outputs in Printed_Outup.txt file
 *                  6. All steps have timings
 *
 *  
 *Compile:          gcc Dilithium.c -o Dilithium -loqs -lcrypto
 *
 *Run:              ./Dilithium
 *
 *Documentation:    Open Quantum Safe Library + OpenSSL Library
 *
 *Created By:       << Saleh Darzi >>
_______________________________________________________________________________*/


// Headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>

#include "srsran/asn1/rrc_nr/Dilithium.h"
#include "srsran/asn1/rrc_nr/Modulized_HIBFSS_Schnorr2.h"

namespace asn1 {
namespace rrc_nr {

#define SIGNATURE_ALG "Dilithium2"





/*************************************************************
				    F u n c t i o n s
**************************************************************/
// Function to measure time in nanoseconds

// Function to print only the first 8 bytes in hex format
void print_short_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (size: %zu bytes): ", label, len);
    for (size_t i = 0; i < 8 && i < len; i++) {
        printf("%02X ", data[i]);
    }
    if (len > 8) {
        printf("...");
    }
    printf("\n");
}

// Function to write full data to file
void write_to_file(FILE *fp, const char *label, const uint8_t *data, size_t len) {
    fprintf(fp, "%s (size: %zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        fprintf(fp, "%02X", data[i]);
        if ((i + 1) % 32 == 0) fprintf(fp, "\n");
    }
    fprintf(fp, "\n\n");
}

// Generate key pair
void generate_keypair(uint8_t *public_key, uint8_t *private_key) {
    OQS_SIG *sig = OQS_SIG_new(SIGNATURE_ALG);
    if (!sig) {
        printf("Failed to initialize Dilithium2\n");
        exit(1);
    }

    double start = get_time_ns();
    if (OQS_SIG_keypair(sig, public_key, private_key) != OQS_SUCCESS) {
        printf("Key generation failed\n");
        exit(1);
    }
    double end = get_time_ns();
    printf("Key generation took %.2f ms\n", (end - start) / 1e6);

    OQS_SIG_free(sig);
}

// Sign message
void sign_message(const uint8_t *private_key, const uint8_t *message, size_t msg_len, uint8_t *signature, size_t *sig_len) {
    OQS_SIG *sig = OQS_SIG_new(SIGNATURE_ALG);
    if (!sig) exit(1);

    double start = get_time_ns();
    if (OQS_SIG_sign(sig, signature, sig_len, message, msg_len, private_key) != OQS_SUCCESS) {
        printf("Signing failed\n");
        exit(1);
    }
    double end = get_time_ns();
    printf("Signing took %.2f ms\n", (end - start) / 1e6);

    OQS_SIG_free(sig);
}

// Verify signature
int verify_signature(const uint8_t *public_key, const uint8_t *message, size_t msg_len, const uint8_t *signature, size_t sig_len) {
    OQS_SIG *sig = OQS_SIG_new(SIGNATURE_ALG);
    if (!sig) exit(1);

    double start = get_time_ns();
    int result = OQS_SIG_verify(sig, message, msg_len, signature, sig_len, public_key);
    double end = get_time_ns();
    printf("Verification took %.2f ms\n", (end - start) / 1e6);

    OQS_SIG_free(sig);
    return result;
}

}
}
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
#include "srsran/asn1/rrc_nr/crypto_utils.h"

#define SIGNATURE_ALG "Dilithium2"






namespace asn1 {
namespace rrc_nr {


/*************************************************************
				    F u n c t i o n s
**************************************************************/


// Function to print only the first 8 bytes in hex format
void print_short_hex(const char *label, const uint8_t *data, size_t len);

// Function to write full data to file
void write_to_file(FILE *fp, const char *label, const uint8_t *data, size_t len);

// Generate key pair
void generate_keypair(uint8_t *public_key, uint8_t *private_key);

// Sign message
void sign_message(const uint8_t *private_key, const uint8_t *message, size_t msg_len, uint8_t *signature, size_t *sig_len);

// Verify signature
int verify_signature(const uint8_t *public_key, const uint8_t *message, size_t msg_len, const uint8_t *signature, size_t sig_len);



}
}
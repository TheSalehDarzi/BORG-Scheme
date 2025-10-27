// 
// 
/**************************************
 *          EC-Schnorr Algorithm            *
 **************************************
 *
 *Compile:          gcc UE.c -o UE -lcrypto -lssl
 * 
 *Run:              ./UE
 *
 *Documentation:    OpenSSL Library
 *
 * Created By:      << Saleh Darzi >>
_______________________________________________________________________________*/



#include "srsran/asn1/UE_EC_SCHNORR.h"

namespace asn1{
namespace rrc_nr{


std::string ec_schnorr_basepath = "/home/masfiqur/5G_cryptobs/credentials/ec_schnorr/";

// void print_hex(const char *label, const unsigned char *buf, size_t len) {
//     printf("%s:\n", label);
//     for (size_t i = 0; i < len; i++) {
//         printf("%02x", buf[i]);
//         if ((i + 1) % 32 == 0) printf("\n");
//     }
//     if (len % 32 != 0) printf("\n");
//     printf("----------------------------------\n");
// }

// double get_time_ns() {
//     struct timespec ts;
//     clock_gettime(CLOCK_MONOTONIC, &ts);
//     return ts.tv_sec * 1e9 + ts.tv_nsec;
// }

unsigned char *read_hex_file_ec_schnorr(const char *filename, size_t *len) {
    FILE *file = fopen((ec_schnorr_basepath+filename).c_str(), "r");
    fseek(file, 0, SEEK_END);
    size_t hexlen = ftell(file);
    rewind(file);
    unsigned char *buf = (unsigned char*)malloc(hexlen / 2);
    for (size_t i = 0; i < hexlen / 2; i++) fscanf(file, "%2hhx", &buf[i]);
    fclose(file);
    *len = hexlen / 2;
    return buf;
}

BIGNUM *read_bn_line_ec_schnorr(FILE *file) {
    char hex[200];
    fgets(hex, sizeof(hex), file);
    hex[strcspn(hex, "\r\n")] = '\0';
    BIGNUM *bn = NULL;
    BN_hex2bn(&bn, hex);
    return bn;
}

EC_KEY *load_pubkey_ec_schnorr(const char *filename) {
    size_t len;
    unsigned char *buf = read_hex_file_ec_schnorr(filename, &len);
    const unsigned char *p = buf;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, len);
    if (!pkey) {
        fprintf(stderr, "ERROR: d2i_PUBKEY failed on %s\n", filename);
        exit(EXIT_FAILURE);
    }
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    EVP_PKEY_free(pkey);
    free(buf);
    return ec_key;
}

int schnorr_verify(EC_KEY *verifier, const unsigned char *msg, size_t msg_len, BIGNUM *r, BIGNUM *s) {
    BN_CTX *ctx = BN_CTX_new();
    const EC_GROUP *group = EC_KEY_get0_group(verifier);
    const EC_POINT *pk = EC_KEY_get0_public_key(verifier);

    BIGNUM *order = BN_new(), *e = BN_new();
    EC_POINT *sG = EC_POINT_new(group);
    EC_POINT *eP = EC_POINT_new(group);
    EC_POINT *R = EC_POINT_new(group);

    EC_GROUP_get_order(group, order, ctx);
    unsigned char r_bytes[28];
    BN_bn2binpad(r, r_bytes, sizeof(r_bytes));

    unsigned char to_hash[28 + msg_len];
    memcpy(to_hash, r_bytes, 28);
    memcpy(to_hash + 28, msg, msg_len);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(to_hash, sizeof(to_hash), hash);
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, e);
    BN_mod(e, e, order, ctx);

    EC_POINT_mul(group, sG, s, NULL, NULL, ctx);
    EC_POINT_mul(group, eP, NULL, pk, e, ctx);
    EC_POINT_invert(group, eP, ctx);
    EC_POINT_add(group, R, sG, eP, ctx);

    BIGNUM *r_verify = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, R, r_verify, NULL, ctx);
    int valid = BN_cmp(r, r_verify) == 0;

    BN_free(order); BN_free(e); BN_free(r_verify);
    EC_POINT_free(sG); EC_POINT_free(eP); EC_POINT_free(R);
    BN_CTX_free(ctx);
    return valid;
}

int run_ec_schnorr_ue(){
    int runs = 1;
    // printf("Enter number of verification runs: ");
    // scanf("%d", &runs);

    // Load keys
    EC_KEY *ckg = load_pubkey_ec_schnorr("PK_CKG.txt");
    EC_KEY *amf = load_pubkey_ec_schnorr("PK_AMF.txt");
    EC_KEY *bs  = load_pubkey_ec_schnorr("PK_BS.txt");

    // Load public key bytes
    size_t len_amf, len_bs;
    unsigned char *amf_bytes = read_hex_file_ec_schnorr("PK_AMF.txt", &len_amf);
    unsigned char *bs_bytes  = read_hex_file_ec_schnorr("PK_BS.txt", &len_bs);

    // Load certs
    FILE *cert_amf_file = fopen((ec_schnorr_basepath+"Certificate_AMF.txt").c_str(), "r");
    BIGNUM *r_amf = read_bn_line_ec_schnorr(cert_amf_file);
    BIGNUM *s_amf = read_bn_line_ec_schnorr(cert_amf_file);
    fclose(cert_amf_file);

    FILE *cert_bs_file = fopen((ec_schnorr_basepath+"Certificate_BS.txt").c_str(), "r");
    BIGNUM *r_bs = read_bn_line_ec_schnorr(cert_bs_file);
    BIGNUM *s_bs = read_bn_line_ec_schnorr(cert_bs_file);
    fclose(cert_bs_file);

    // Load message
    unsigned char msg[MSG_LEN];
    unsigned char temp[] = "This is a large message to be signed. This immitates network packet, the SIB1!";
    memcpy(msg,temp,MSG_LEN);
    // FILE *fmsg = fopen((ec_schnorr_basepath+"message.txt").c_str(), "rb");
    // fread(msg, 1, MSG_LEN, fmsg);
    // fclose(fmsg);
    print_hex("Message", msg, MSG_LEN);

    FILE *fsig = fopen((ec_schnorr_basepath+"signature.txt").c_str(), "r");
    double total_time = 0.0;

    for (int i = 0; i < runs; i++) {
        BIGNUM *r_sig = read_bn_line_ec_schnorr(fsig);
        BIGNUM *s_sig = read_bn_line_ec_schnorr(fsig);

        double start = get_time_ns();
        int cert1_ok = schnorr_verify(ckg, amf_bytes, len_amf, r_amf, s_amf);
        int cert2_ok = schnorr_verify(amf, bs_bytes, len_bs, r_bs, s_bs);
        int sig_ok   = schnorr_verify(bs, msg, MSG_LEN, r_sig, s_sig);
        double end = get_time_ns();

        printf("Run #%d - Cert1: %s, Cert2: %s, Signature: %s\n", i + 1,
               cert1_ok ? "✅" : "❌",
               cert2_ok ? "✅" : "❌",
               sig_ok   ? "✅" : "❌");

        total_time += (end - start) / 1e9;
        BN_free(r_sig); BN_free(s_sig);
    }

    fclose(fsig);
    EC_KEY_free(ckg); EC_KEY_free(amf); EC_KEY_free(bs);
    BN_free(r_amf); BN_free(s_amf); BN_free(r_bs); BN_free(s_bs);
    free(amf_bytes); free(bs_bytes);

    printf("Average Verification Time: %.9f sec\n", total_time / runs);
    return 0;
}

// int main() {
//     run_ec_schnorr_ue();
    
// }


}
}
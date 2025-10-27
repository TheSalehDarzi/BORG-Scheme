// 
// 
/**************************************
 *          EC-Schnorr Algorithm            *
 **************************************
 *
 *Compile:          gcc AMF.c -o AMF -lcrypto -lssl
 * 
 *Run:              ./BS
 *
 *Documentation:    OpenSSL Library
 *
 * Created By:      << Saleh Darzi >>
_______________________________________________________________________________*/


#include "srsran/asn1/rrc_nr/AMF_EC_SCHNORR.h"

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

void write_file(const char *filename, const unsigned char *data, size_t len) {
    FILE *f = fopen((ec_schnorr_basepath+filename).c_str(), "w");
    for (size_t i = 0; i < len; i++) fprintf(f, "%02x", data[i]);
    fprintf(f, "\n");
    fclose(f);
}

unsigned char *serialize_pubkey(EC_KEY *key, size_t *len) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, EC_KEY_dup(key)) != 1) {
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *buf = NULL;
    int l = i2d_PUBKEY(pkey, &buf);
    *len = l;
    EVP_PKEY_free(pkey);
    return buf;
}

unsigned char *serialize_privkey(EC_KEY *key, size_t *len) {
    unsigned char *buf = NULL;
    int l = i2d_ECPrivateKey(key, &buf);
    *len = l;
    return buf;
}

void schnorr_sign_pubkey(EC_KEY *signer, const unsigned char *pub_bytes, size_t len, BIGNUM **r_out, BIGNUM **s_out) {
    BN_CTX *ctx = BN_CTX_new();
    const EC_GROUP *group = EC_KEY_get0_group(signer);
    const BIGNUM *sk = EC_KEY_get0_private_key(signer);

    BIGNUM *k = BN_new(), *r = BN_new(), *s = BN_new(), *e = BN_new(), *order = BN_new();
    EC_POINT *R = EC_POINT_new(group);

    EC_GROUP_get_order(group, order, ctx);
    BN_rand_range(k, order);
    EC_POINT_mul(group, R, k, NULL, NULL, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, R, r, NULL, ctx);

    unsigned char r_bytes[28];
    BN_bn2binpad(r, r_bytes, sizeof(r_bytes));
    unsigned char to_hash[28 + len];
    memcpy(to_hash, r_bytes, 28);
    memcpy(to_hash + 28, pub_bytes, len);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(to_hash, sizeof(to_hash), hash);
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, e);
    BN_mod(e, e, order, ctx);

    BN_mod_mul(s, e, sk, order, ctx);
    BN_mod_add(s, s, k, order, ctx);

    *r_out = BN_dup(r);
    *s_out = BN_dup(s);

    EC_POINT_free(R);
    BN_free(k); BN_free(r); BN_free(s); BN_free(e); BN_free(order);
    BN_CTX_free(ctx);
}


int run_ec_schnorr_amf(){
    EC_KEY *ckg = EC_KEY_new_by_curve_name(CURVE);
    EC_KEY *amf = EC_KEY_new_by_curve_name(CURVE);
    EC_KEY *bs  = EC_KEY_new_by_curve_name(CURVE);
    EC_KEY_generate_key(ckg);
    EC_KEY_generate_key(amf);
    EC_KEY_generate_key(bs);

    size_t len;
    unsigned char *buf;

    // PK_CKG
    buf = serialize_pubkey(ckg, &len);
    write_file("PK_CKG.txt", buf, len);
    print_hex("PK_CKG", buf, len);
    OPENSSL_free(buf);

    // PK_AMF
    buf = serialize_pubkey(amf, &len);
    write_file("PK_AMF.txt", buf, len);
    print_hex("PK_AMF", buf, len);
    BIGNUM *r1, *s1;
    schnorr_sign_pubkey(ckg, buf, len, &r1, &s1);
    FILE *cert_amf = fopen((ec_schnorr_basepath+"Certificate_AMF.txt").c_str(), "w");
    char *r1_hex = BN_bn2hex(r1);
    char *s1_hex = BN_bn2hex(s1);
    fprintf(cert_amf, "%s\n%s\n", r1_hex, s1_hex);
    OPENSSL_free(r1_hex); OPENSSL_free(s1_hex);
    fclose(cert_amf);
    OPENSSL_free(buf); BN_free(r1); BN_free(s1);

    // PK_BS
    buf = serialize_pubkey(bs, &len);
    write_file("PK_BS.txt", buf, len);
    print_hex("PK_BS", buf, len);
    BIGNUM *r2, *s2;
    schnorr_sign_pubkey(amf, buf, len, &r2, &s2);
    FILE *cert_bs = fopen((ec_schnorr_basepath+"Certificate_BS.txt").c_str(), "w");
    char *r2_hex = BN_bn2hex(r2);
    char *s2_hex = BN_bn2hex(s2);
    fprintf(cert_bs, "%s\n%s\n", r2_hex, s2_hex);
    OPENSSL_free(r2_hex); OPENSSL_free(s2_hex);
    fclose(cert_bs);
    OPENSSL_free(buf); BN_free(r2); BN_free(s2);

    // SK_BS
    buf = serialize_privkey(bs, &len);
    write_file("sk_BS.txt", buf, len);
    print_hex("sk_BS", buf, len);
    OPENSSL_free(buf);

    EC_KEY_free(ckg); EC_KEY_free(amf); EC_KEY_free(bs);
    return 0;
}

// int main() {
//     run_ec_schnorr_amf();
// }

}
}
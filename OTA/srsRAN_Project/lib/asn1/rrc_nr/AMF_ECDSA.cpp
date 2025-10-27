#include "srsran/asn1/rrc_nr/AMF_ECDSA.h"


namespace asn1{
namespace rrc_nr{


std::string ecdsa_basepath = "/home/masfiqur/5G_cryptobs/credentials/ecdsa/";


// double get_time_ns() {
//     struct timespec ts;
//     clock_gettime(CLOCK_MONOTONIC, &ts);
//     return ts.tv_sec * 1e9 + ts.tv_nsec;
// }

void write_to_file_ecdsa(const char *filename, const unsigned char *data, size_t len) {
    FILE *file = fopen((ecdsa_basepath+filename).c_str(), "w");
    for (size_t i = 0; i < len; i++)
        fprintf(file, "%02x", data[i]);
    fprintf(file, "\n");
    fclose(file);
}

// void print_hex(const char *label, const unsigned char *data, size_t len) {
//     printf("%s:\n", label);
//     for (size_t i = 0; i < len; i++) {
//         printf("%02x", data[i]);
//         if ((i + 1) % 32 == 0) printf("\n");
//     }
//     if (len % 32 != 0) printf("\n");
//     printf("----------------------------------------\n");
// }

unsigned char *serialize_pubkey_ecdsa(EVP_PKEY *pkey, size_t *len) {
    unsigned char *buf = NULL;
    int l = i2d_PUBKEY(pkey, &buf);
    *len = l;
    return buf;
}

unsigned char *serialize_privkey_ecdsa(EVP_PKEY *pkey, size_t *len) {
    unsigned char *buf = NULL;
    int l = i2d_PrivateKey(pkey, &buf);
    *len = l;
    return buf;
}

EVP_PKEY *generate_keypair_ecdsa() {
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ECDSA_CURVE_NAME);
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

unsigned char *sign_ecdsa(EVP_PKEY *signer, const unsigned char *data, size_t len, size_t *sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, signer);
    EVP_DigestSign(ctx, NULL, sig_len, data, len);
    unsigned char *sig = (unsigned char*)OPENSSL_malloc(*sig_len);
    EVP_DigestSign(ctx, sig, sig_len, data, len);
    EVP_MD_CTX_free(ctx);
    return sig;
}

int run_ecdsa_amf(){
    OpenSSL_add_all_algorithms();

    EVP_PKEY *ckg = generate_keypair_ecdsa();
    EVP_PKEY *amf = generate_keypair_ecdsa();
    EVP_PKEY *bs  = generate_keypair_ecdsa();
    size_t len;
    unsigned char *buf;

    // PK_CKG
    buf = serialize_pubkey_ecdsa(ckg, &len);
    write_to_file_ecdsa("PK_CKG.txt", buf, len);
    print_hex("PK_CKG", buf, len);
    OPENSSL_free(buf);

    // PK_AMF
    buf = serialize_pubkey_ecdsa(amf, &len);
    write_to_file_ecdsa("PK_AMF.txt", buf, len);
    print_hex("PK_AMF", buf, len);
    OPENSSL_free(buf);

    // PK_BS
    buf = serialize_pubkey_ecdsa(bs, &len);
    write_to_file_ecdsa("PK_BS.txt", buf, len);
    print_hex("PK_BS", buf, len);
    OPENSSL_free(buf);

    // SK_BS
    buf = serialize_privkey_ecdsa(bs, &len);
    write_to_file_ecdsa("sk_BS.txt", buf, len);
    print_hex("SK_BS", buf, len);
    OPENSSL_free(buf);

    // Certificates
    unsigned char *amf_buf = serialize_pubkey_ecdsa(amf, &len);
    size_t sig_len;
    unsigned char *cert_amf = sign_ecdsa(ckg, amf_buf, len, &sig_len);
    write_to_file_ecdsa("Certificate_AMF.txt", cert_amf, sig_len);
    print_hex("Certificate_AMF (signed by CKG)", cert_amf, sig_len);
    OPENSSL_free(cert_amf);

    unsigned char *bs_buf = serialize_pubkey_ecdsa(bs, &len);
    unsigned char *cert_bs = sign_ecdsa(amf, bs_buf, len, &sig_len);
    write_to_file_ecdsa("Certificate_BS.txt", cert_bs, sig_len);
    print_hex("Certificate_BS (signed by AMF)", cert_bs, sig_len);
    OPENSSL_free(cert_bs);

    EVP_PKEY_free(ckg); EVP_PKEY_free(amf); EVP_PKEY_free(bs);
    OPENSSL_free(amf_buf); OPENSSL_free(bs_buf);
    return 0;
}

// int main() {
//     run_ecdsa_amf();
// }


}
}
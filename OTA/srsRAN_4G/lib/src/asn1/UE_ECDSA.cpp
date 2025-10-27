#include "srsran/asn1/UE_ECDSA.h"


namespace asn1{
namespace rrc_nr{

std::string ecdsa_basepath = "/home/masfiqur/5G_cryptobs/credentials/ecdsa/";

// double get_time_ns() {
//     struct timespec ts;
//     clock_gettime(CLOCK_MONOTONIC, &ts);
//     return ts.tv_sec * 1e9 + ts.tv_nsec;
// }

unsigned char *read_hex_file_ecdsa(const char *filename, size_t *len) {
    FILE *file = fopen((ecdsa_basepath+filename).c_str(), "r");
    fseek(file, 0, SEEK_END);
    size_t hexlen = ftell(file);
    rewind(file);

    unsigned char *buf = (unsigned char*)malloc(hexlen / 2);
    for (size_t i = 0; i < hexlen / 2; i++) {
        fscanf(file, "%2hhx", &buf[i]);
    }
    fclose(file);
    *len = hexlen / 2;
    return buf;
}

EVP_PKEY *load_pubkey_ecdsa(const char *filename) {
    size_t len;
    unsigned char *buf = read_hex_file_ecdsa(filename, &len);
    const unsigned char *p = buf;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &p, len);
    free(buf);
    return key;
}

int verify_ecdsa(EVP_PKEY *key, const unsigned char *msg, size_t msglen, unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key);
    int valid = EVP_DigestVerify(ctx, sig, siglen, msg, msglen);
    EVP_MD_CTX_free(ctx);
    return valid == 1;
}


int run_ecdsa_ue(){
    int runs =1;
    // printf("Enter number of verification runs: ");
    // scanf("%d", &runs);

    EVP_PKEY *pk_ckg = load_pubkey_ecdsa("PK_CKG.txt");
    EVP_PKEY *pk_amf = load_pubkey_ecdsa("PK_AMF.txt");
    EVP_PKEY *pk_bs  = load_pubkey_ecdsa("PK_BS.txt");

    size_t cert_amf_len, cert_bs_len;
    unsigned char *cert_amf = read_hex_file_ecdsa("Certificate_AMF.txt", &cert_amf_len);
    unsigned char *cert_bs  = read_hex_file_ecdsa("Certificate_BS.txt", &cert_bs_len);

    size_t amf_len, bs_len;
    unsigned char *amf_buf = read_hex_file_ecdsa("PK_AMF.txt", &amf_len);
    unsigned char *bs_buf  = read_hex_file_ecdsa("PK_BS.txt", &bs_len);

    unsigned char msg[MSG_LEN];
    unsigned char temp[] = "This is a large message to be signed. This immitates network packet, the SIB1!";
    memcpy(msg,temp,MSG_LEN);

    // unsigned char msg[MSG_LEN];
    // FILE *fmsg = fopen((ecdsa_basepath+"message.txt").c_str(), "rb");
    // fread(msg, 1, MSG_LEN, fmsg);
    // fclose(fmsg);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(msg, MSG_LEN, hash);

    double total_time = 0.0;
    FILE *fsig = fopen((ecdsa_basepath+"signature.txt").c_str(), "r");

    for (int i = 0; i < runs; i++) {
        size_t sig_len;
        unsigned char sig[MAX_SIG];
        for (size_t j = 0; j < MAX_SIG; j++) {
            if (fscanf(fsig, "%2hhx", &sig[j]) != 1) break;
        }

        double start = get_time_ns();
        int cert1 = verify_ecdsa(pk_ckg, amf_buf, amf_len, cert_amf, cert_amf_len);
        int cert2 = verify_ecdsa(pk_amf, bs_buf, bs_len, cert_bs, cert_bs_len);
        int valid = verify_ecdsa(pk_bs, hash, SHA256_DIGEST_LENGTH, sig, cert_bs_len);
        double end = get_time_ns();
        total_time += (end - start) / 1e9;

        printf("Run #%d: Cert1: %s, Cert2: %s, Signature: %s\n", i + 1,
               cert1 ? "✅" : "❌", cert2 ? "✅" : "❌", valid ? "✅" : "❌");
    }

    fclose(fsig);
    EVP_PKEY_free(pk_ckg); EVP_PKEY_free(pk_amf); EVP_PKEY_free(pk_bs);
    free(cert_amf); free(cert_bs); free(amf_buf); free(bs_buf);

    printf("Avg. Verification Time: %.9f sec\n", total_time / runs);
    return 0;
}

// int main() {
//     run_ecdsa_ue();
// }

}
}
#include "srsran/asn1/rrc_nr/BS_ECDSA.h"




namespace asn1{
namespace rrc_nr{
    
    
// std::string ecdsa_basepath = "/home/masfiqur/5G_cryptobs/credentials/ecdsa/";

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

EVP_PKEY *load_privkey_ecdsa(const char *filename) {
    size_t len;
    unsigned char *buf = read_hex_file_ecdsa(filename, &len);
    if (!buf || len == 0) {
        fprintf(stderr, "Error reading secret key file: %s\n", filename);
        exit(1);
    }

    const unsigned char *p = buf;
    EVP_PKEY *key = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, len);
    if (!key) {
        fprintf(stderr, "Failed to parse EC private key from file: %s\n", filename);
        exit(1);
    }

    free(buf);
    return key;
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

int run_ecdsa_bs(){
    int runs = 1;
    // printf("Enter number of signing runs: ");
    // scanf("%d", &runs);

    EVP_PKEY *sk_bs = load_privkey_ecdsa("sk_BS.txt");


    unsigned char msg[MSG_LEN];
    unsigned char temp[] = "This is a large message to be signed. This immitates network packet, the SIB1!";
    memcpy(msg,temp,MSG_LEN);
    // unsigned char msg[MSG_SIZE];
    // FILE *fmsg = fopen((ecdsa_basepath+"message.txt").c_str(), "rb");
    // if (!fmsg) {
    //     fprintf(stderr, "message.txt not found!\n");
    //     return 1;
    // }
    // if (fread(msg, 1, MSG_SIZE, fmsg) != MSG_SIZE) {
    //     fprintf(stderr, "message.txt must be exactly %d bytes.\n", MSG_SIZE);
    //     fclose(fmsg);
    //     return 1;
    // }
    // fclose(fmsg);

    print_hex("Message", msg, MSG_LEN);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(msg, MSG_LEN, hash);

    double total_time = 0.0;
    FILE *fsig = fopen((ecdsa_basepath+"signature.txt").c_str(), "w");

    for (int i = 0; i < runs; i++) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        size_t sig_len;
        double start = get_time_ns();
        EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, sk_bs);
        EVP_DigestSign(ctx, NULL, &sig_len, hash, SHA256_DIGEST_LENGTH);
        unsigned char *sig = (unsigned char*)OPENSSL_malloc(sig_len);
        EVP_DigestSign(ctx, sig, &sig_len, hash, SHA256_DIGEST_LENGTH);
        double end = get_time_ns();
        total_time += (end - start) / 1e9;

        for (size_t j = 0; j < sig_len; j++)
            fprintf(fsig, "%02x", sig[j]);
        fprintf(fsig, "\n");

        // Print to terminal
        printf("Run #%d Signature:\n", i + 1);
        print_hex("Signature", sig, sig_len);

        OPENSSL_free(sig);
        EVP_MD_CTX_free(ctx);
    }

    fclose(fsig);
    EVP_PKEY_free(sk_bs);
    printf("Average Signing Time: %.9f sec\n", total_time / runs);
    return 0;
}

// int main() {
//     bool ecdsa_amf_required = true;

//     if(ecdsa_amf_required) run_ecdsa_amf();
    
//     run_ecdsa_bs();
// }

}
}
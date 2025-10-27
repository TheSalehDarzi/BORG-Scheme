#include "srsran/asn1/rrc_nr/BS_EC_SCHNORR.h"


namespace asn1{
namespace rrc_nr{


//std::string ec_schnorr_basepath = "/home/masfiqur/5G_cryptobs/credentials/ec_schnorr/";

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
    for (size_t i = 0; i < hexlen / 2; i++) {
        fscanf(file, "%2hhx", &buf[i]);
    }
    fclose(file);
    *len = hexlen / 2;
    return buf;
}

EC_KEY *load_privkey_ec_schnorr(const char *filename) {
    size_t len;
    unsigned char *buf = read_hex_file_ec_schnorr(filename, &len);
    const unsigned char *p = buf;
    EC_KEY *key = d2i_ECPrivateKey(NULL, &p, len);
    free(buf);
    return key;
}

void schnorr_sign_msg(EC_KEY *key, const unsigned char *msg, size_t msg_len, BIGNUM **r_out, BIGNUM **s_out) {
    BN_CTX *ctx = BN_CTX_new();
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *sk = EC_KEY_get0_private_key(key);

    BIGNUM *k = BN_new(), *r = BN_new(), *s = BN_new(), *e = BN_new(), *order = BN_new();
    EC_POINT *R = EC_POINT_new(group);

    EC_GROUP_get_order(group, order, ctx);
    BN_rand_range(k, order);
    EC_POINT_mul(group, R, k, NULL, NULL, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, R, r, NULL, ctx);

    unsigned char r_bytes[28];
    BN_bn2binpad(r, r_bytes, sizeof(r_bytes));

    unsigned char to_hash[28 + msg_len];
    memcpy(to_hash, r_bytes, 28);
    memcpy(to_hash + 28, msg, msg_len);
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


int run_ec_schnorr_bs(){
    int runs = 1;
    //printf("Enter number of signing runs: ");
    //scanf("%d", &runs);

    // Read message
    unsigned char msg[MSG_LEN];
    unsigned char temp[] = "This is a large message to be signed. This immitates network packet, the SIB1!";
    memcpy(msg,temp,MSG_LEN);
    // FILE *fmsg = fopen((ec_schnorr_basepath+"message.txt").c_str(), "rb");
    // if (!fmsg) {
    //     fprintf(stderr, "message.txt not found!\n");
    //     return 1;
    // }
    // if (fread(msg, 1, MSG_LEN, fmsg) != MSG_LEN) {
    //     fprintf(stderr, "message.txt must be exactly %d bytes.\n", MSG_LEN);
    //     fclose(fmsg);
    //     return 1;
    // }
    // fclose(fmsg);
    print_hex("Message", msg, MSG_LEN);

    // Load secret key
    EC_KEY *bs_key = load_privkey_ec_schnorr("sk_BS.txt");

    FILE *fsig = fopen((ec_schnorr_basepath+"signature.txt").c_str(), "w");
    double total_time = 0.0;

    for (int i = 0; i < runs; i++) {
        BIGNUM *r = NULL, *s = NULL;

        double start = get_time_ns();
        schnorr_sign_msg(bs_key, msg, MSG_LEN, &r, &s);
        double end = get_time_ns();

        total_time += (end - start) / 1e9;

        char *r_hex = BN_bn2hex(r);
        char *s_hex = BN_bn2hex(s);

        fprintf(fsig, "%s\n%s\n", r_hex, s_hex);
        printf("Run #%d Signature:\n", i + 1);
        printf("r = %s\ns = %s\n----------------------------------\n", r_hex, s_hex);

        OPENSSL_free(r_hex);
        OPENSSL_free(s_hex);
        BN_free(r);
        BN_free(s);
    }

    fclose(fsig);
    EC_KEY_free(bs_key);

    printf("Average Signing Time: %.9f sec\n", total_time / runs);
    return 0;
}

// int main() {
//     bool run_amf = true;
//     if(run_amf)run_ec_schnorr_amf();
//     run_ec_schnorr_bs();
// }


}
}
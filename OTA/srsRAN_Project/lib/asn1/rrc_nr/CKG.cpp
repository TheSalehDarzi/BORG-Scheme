
// 
// 
/**************************************
 *          Core Key Generator           *
 **************************************

 * 
 *
 *Compile:          g++ CKG.cpp Modulized_HIBFSS_Schnorr2.cpp -o ckg -lcrypto -lssl
 * 
 *Run:              ./ckg
 *
 *Documentation:    OpenSSL Library
 *
 * Created By:      << Mirza Masfiqur Rahman >>
_______________________________________________________________________________*/
#include "srsran/asn1/rrc_nr/CKG.h"

namespace asn1{
namespace rrc_nr{


std::string basepath = "/home/masfiqur/5G_cryptobs/credentials/";

BIGNUM *hj = NULL, *zj = NULL;
EC_POINT *Rj = NULL;
int k =3;
int sign_level =2;

/*======================================
            BIGNUM Double Pointer Saving Function
========================================*/ 
void save_bignum_dp(BIGNUM** bignumPtr, const std::string& filename) {
    if (!bignumPtr || !(*bignumPtr)) return;

    // Convert to binary representation
    int len = BN_num_bytes(*bignumPtr);
    unsigned char* buffer = new unsigned char[len];
    BN_bn2bin(*bignumPtr, buffer);

    // Save binary to file
    std::ofstream out(filename, std::ios::binary);
    out.write(reinterpret_cast<char*>(&len), sizeof(len)); // Save length first
    out.write(reinterpret_cast<char*>(buffer), len);
    out.close();

    delete[] buffer;
}


/*======================================
            BIGNUM Double Pointer Loading Function
========================================*/ 
BIGNUM** load_bignum_dp(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) return nullptr;

    int len;
    in.read(reinterpret_cast<char*>(&len), sizeof(len));
    
    unsigned char* buffer = new unsigned char[len];
    in.read(reinterpret_cast<char*>(buffer), len);
    
    // Convert back to BIGNUM
    BIGNUM* bn = BN_bin2bn(buffer, len, nullptr);
    
    BIGNUM** bignumPtr = new BIGNUM*(nullptr);
    *bignumPtr = bn;
    //printf("length is %d\n", len);
    delete[] buffer;
    in.close();
    return bignumPtr;
}



// void save_bignum_array(BIGNUM** bn_array, size_t count, const std::string& filename) {
//     std::ofstream out(filename, std::ios::binary);
//     if (!out.is_open()) return;
//     out.write(reinterpret_cast<const char*>(&count), sizeof(count));  // Save number of BIGNUMs
//     for (size_t i = 0; i <= count; i++) {
//         int len = BN_num_bytes(bn_array[i]);
//         std::vector<unsigned char> buffer(len);
//         BN_bn2bin(bn_array[i], buffer.data());
//         out.write(reinterpret_cast<const char*>(&len), sizeof(len));   // Save length
//         out.write(reinterpret_cast<const char*>(buffer.data()), len);  // Save bytes
//     }
//     out.close();
// }

// BIGNUM** load_bignum_array(const std::string& filename) {
//     std::ifstream in(filename, std::ios::binary);
//     if (!in.is_open()) return nullptr;
//     size_t count;
//     in.read(reinterpret_cast<char*>(&count), sizeof(count));
//     //printf("Reading %ld BIGNUM objects\n",count);
//     BIGNUM** bn_array = new BIGNUM*[count+1];
//     for (size_t i = 0; i <= count; i++) {
//         int len;
//         in.read(reinterpret_cast<char*>(&len), sizeof(len));
//         std::vector<unsigned char> buffer(len);
//         in.read(reinterpret_cast<char*>(buffer.data()), len);
//         bn_array[i] = BN_bin2bn(buffer.data(), len, nullptr);
//     }
//     in.close(); 
//     return bn_array;
// }




void save_bignum_array_nullable(BIGNUM** bn_array, size_t count, const std::string& filename) {
    std::ofstream out(filename, std::ios::binary);
    if (!out.is_open()) return;

    out.write(reinterpret_cast<const char*>(&count), sizeof(count));  // Save number of elements

    for (size_t i = 0; i <= count; i++) {
        uint8_t is_present = (bn_array[i] != NULL) ? 1 : 0;
        out.write(reinterpret_cast<const char*>(&is_present), sizeof(is_present));  // Save null flag

        if (is_present) {
            int len = BN_num_bytes(bn_array[i]);
            std::vector<unsigned char> buffer(len);
            BN_bn2bin(bn_array[i], buffer.data());

            out.write(reinterpret_cast<const char*>(&len), sizeof(len));       // Save length
            out.write(reinterpret_cast<const char*>(buffer.data()), len);      // Save data
        }
    }

    out.close();
}



BIGNUM** load_bignum_array_nullable(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) return nullptr;

    size_t count;
    in.read(reinterpret_cast<char*>(&count), sizeof(count));
    //printf("Reading %ld BIGNUM objects\n", count);
    BIGNUM** bn_array = new BIGNUM*[count+1];

    for (size_t i = 0; i <= count; i++) {
        uint8_t is_present;
        in.read(reinterpret_cast<char*>(&is_present), sizeof(is_present));

        if (is_present) {
            int len;
            in.read(reinterpret_cast<char*>(&len), sizeof(len));

            std::vector<unsigned char> buffer(len);
            in.read(reinterpret_cast<char*>(buffer.data()), len);

            bn_array[i] = BN_bin2bn(buffer.data(), len, nullptr);
        } else {
            bn_array[i] = NULL;  // Null entry
        }
    }

    in.close();
    return bn_array;
}

/*======================================
            BIGNUM Single Pointer Saving Function
========================================*/ 
void save_bignum_sp(BIGNUM* bn, const std::string& filename) {
    if (!bn) return;

    int len = BN_num_bytes(bn);
    unsigned char* buffer = new unsigned char[len];
    BN_bn2bin(bn, buffer);

    std::ofstream out(filename, std::ios::binary);
    out.write(reinterpret_cast<char*>(&len), sizeof(len)); // write length
    out.write(reinterpret_cast<char*>(buffer), len);
    out.close();

    delete[] buffer;
}


/*======================================
            BIGNUM Single Pointer Loading Function
========================================*/ 
BIGNUM* load_bignum_sp(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) return nullptr;
    printf("yo\n");
    int len;
    in.read(reinterpret_cast<char*>(&len), sizeof(len));
    unsigned char* buffer = new unsigned char[len];
    in.read(reinterpret_cast<char*>(buffer), len);

    BIGNUM* bn = BN_bin2bn(buffer, len, nullptr);
    printf("yo\n");
    delete[] buffer;
    in.close();
    return bn;
}





void save_ec_point_sp(EC_GROUP* group, EC_POINT* point, const std::string& filename, BN_CTX* ctx) {
    if (!group || !point) return;

    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, ctx);
    std::vector<unsigned char> buffer(len);

    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buffer.data(), len, ctx);

    std::ofstream out(filename, std::ios::binary);
    out.write(reinterpret_cast<char*>(&len), sizeof(len));
    out.write(reinterpret_cast<char*>(buffer.data()), len);
    out.close();
}



EC_POINT* load_ec_point_sp(EC_GROUP* group, const std::string& filename, BN_CTX* ctx) {
    if (!group) return nullptr;

    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) return nullptr;

    size_t len;
    in.read(reinterpret_cast<char*>(&len), sizeof(len));
    std::vector<unsigned char> buffer(len);
    in.read(reinterpret_cast<char*>(buffer.data()), len);
    in.close();

    EC_POINT* pt = EC_POINT_new(group);
    if (!EC_POINT_oct2point(group, pt, buffer.data(), len, ctx)) {
        EC_POINT_free(pt);
        return nullptr;
    }
    return pt;
    
}


void save_unsigned_char_array(const unsigned char* data, size_t len, const std::string& filename) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) return;

    out.write(reinterpret_cast<const char*>(&len), sizeof(len)); // save length first
    out.write(reinterpret_cast<const char*>(data), len);         // then data
    out.close();
}


unsigned char* load_unsigned_char_array(size_t& len_out, const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) return nullptr;

    size_t len;
    in.read(reinterpret_cast<char*>(&len), sizeof(len));         // read length

    unsigned char* data = new unsigned char[len];
    in.read(reinterpret_cast<char*>(data), len);                 // read data
    in.close();

    len_out = len;
    return data;
}



void save_ec_point_array(EC_GROUP* group, EC_POINT** points, size_t count, const std::string& filename, BN_CTX* ctx) {
    std::ofstream out(filename, std::ios::binary);
    if (!out.is_open()) return;

    out.write(reinterpret_cast<const char*>(&count), sizeof(count)); // Save number of points
    for (size_t i = 0; i <= count; i++) {
        size_t len = EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, ctx);
        std::vector<unsigned char> buffer(len);
        EC_POINT_point2oct(group, points[i], POINT_CONVERSION_UNCOMPRESSED, buffer.data(), len, ctx);

        out.write(reinterpret_cast<const char*>(&len), sizeof(len));       // Write length
        out.write(reinterpret_cast<const char*>(buffer.data()), len);      // Write bytes
    }

    out.close();
}


EC_POINT** load_ec_point_array(EC_GROUP* group, const std::string& filename, BN_CTX* ctx) {
    std::ifstream in(filename, std::ios::binary);
    if (!in.is_open()) return nullptr;

    size_t count;
    in.read(reinterpret_cast<char*>(&count), sizeof(count)); // Read number of points
    //printf("Reading %ld EC_POINT objects\n", count);
    EC_POINT** points = new EC_POINT*[count+1];
    for (size_t i = 0; i <= count; i++) {
        size_t len;
        in.read(reinterpret_cast<char*>(&len), sizeof(len)); // Read length
        std::vector<unsigned char> buffer(len);
        in.read(reinterpret_cast<char*>(buffer.data()), len); // Read bytes

        EC_POINT* point = EC_POINT_new(group);
        if (!EC_POINT_oct2point(group, point, buffer.data(), len, ctx)) {
            EC_POINT_free(point);
            point = nullptr;
        }

        points[i] = point;
    }

    in.close();
    return points;
}


/*======================================
            DILITHIUM Primitives Function
========================================*/ 
// int generate_primitives_dilithium(){
//     FILE *fp = fopen("Printed_Output.txt", "w");
//     if (!fp) {
//         printf("Error: Could not open file for writing.\n");
//         return 1;
//     }

//     // Get sizes
//     OQS_SIG *sig = OQS_SIG_new(SIGNATURE_ALG);
//     size_t pk_len = sig->length_public_key;
//     size_t sk_len = sig->length_secret_key;
//     size_t sig_len_max = sig->length_signature;
//     OQS_SIG_free(sig);

//     // Keys
//     uint8_t Global_CA_pk[pk_len], Global_CA_sk[sk_len];
//     uint8_t CKG_pk[pk_len], CKG_sk[sk_len];
//     uint8_t BS_pk[pk_len], BS_sk[sk_len];

    
    
//     // Key Generation Step
//     printf("\n--------- Key Generation ---------\n");
//     generate_keypair(Global_CA_pk, Global_CA_sk);
//     generate_keypair(CKG_pk, CKG_sk);
//     generate_keypair(BS_pk, BS_sk);

//     print_short_hex("Global_CA Public Key", Global_CA_pk, pk_len);
//     print_short_hex("CKG Public Key", CKG_pk, pk_len);
//     print_short_hex("BS Public Key", BS_pk, pk_len);

//     write_to_file(fp, "Global_CA Public Key", Global_CA_pk, pk_len);
//     write_to_file(fp, "CKG Public Key", CKG_pk, pk_len);
//     write_to_file(fp, "BS Public Key", BS_pk, pk_len);

    
    
//     // Generate Certificates
//     uint8_t CKG_cert[sig_len_max];
//     size_t CKG_cert_len;
//     uint8_t BS_cert[sig_len_max];
//     size_t BS_cert_len;
//     return 1;
// }

/*======================================
            HIBFSS Primitives Function
========================================*/ 
int generate_primitives_hibfss(){
    // Initialize OpenSSL objects
    EC_GROUP *curve = NULL;
    BIGNUM *sk = NULL, *order = NULL;
    //EC_POINT *g = NULL;
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
    //g = (EC_POINT *)EC_GROUP_get0_generator(curve);
    order = BN_new();
    if (!EC_GROUP_get_order(curve, order, ctx)) {
        fprintf(stderr, "Error getting curve order\n");
        EC_GROUP_free(curve);
        BN_CTX_free(ctx);
        return EXIT_FAILURE;
    }



//====================================== System Setup Algorithm ======================================    
    double setup_start_time = get_time_ns();

    EC_POINT *PK0 = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    system_setup(curve, &PK0, &sk, order, ctx, hash);

    double setup_end_time = get_time_ns();

    double elapsed_time_setup = (setup_end_time - setup_start_time) / 1e9;  // Convert ns to seconds
    printf("System Setup phase took: %.9f seconds\n", elapsed_time_setup);




//====================================== Key Extraction Algorithm ======================================
    printf("\n==================== KeyExtract Algorithm ====================\n");
    
    printf("The Max Hierrachial Level is: %d",k);
    //printf("Enter the Hierarchical Level k: ");
    //scanf("%d", &k);

    EC_POINT **vec_QIDk;
    BIGNUM **vec_hIDk;
    BIGNUM **vec_skIDk;
    key_extract(k, curve, PK0, sk, order, ctx, &vec_QIDk, &vec_hIDk, &vec_skIDk, hash);
    
    
    save_ec_point_sp(curve, PK0, basepath+"PK0.bin",ctx);
    save_bignum_sp(sk,basepath+"sk.bin");
    save_bignum_sp(order,basepath+"order.bin");
    
    //save_ec_point_dp(curve, vec_QIDk,"vec_QIDk.bin",ctx);
    save_ec_point_array(curve, vec_QIDk, k, basepath+"vec_QIDk.bin", ctx);
    //save_bignum_dp(vec_hIDk,"vec_hIDk.bin");
    save_bignum_array_nullable(vec_hIDk, k, basepath+"vec_hIDk.bin");
    //save_bignum_dp(vec_skIDk,"vec_skIDk.bin");
    save_bignum_array_nullable(vec_skIDk, k, basepath+"vec_skIDk.bin");
    save_unsigned_char_array(hash,sizeof(hash),basepath+"hash.bin");

    // Cleanup
    // BN_free(rj);
    // BN_free(zj);
    // //BN_free(hj);
    // EC_POINT_free(Rj);
    return EXIT_SUCCESS;

}


int do_sign_hibfss(unsigned char* message, int message_length){
    printf("\n==================== Signing Algorithm ====================\n");

    EC_GROUP *curve = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM **vec_skIDk = NULL;
    BIGNUM *order = NULL; 
    
    EC_POINT **vec_QIDk = NULL;
    unsigned char* hash = new unsigned char[SHA256_DIGEST_LENGTH];

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
    
    //vec_skIDk = load_bignum_dp("vec_skIDk.bin");
    vec_skIDk = load_bignum_array_nullable(basepath+"vec_skIDk.bin");

    //vec_QIDk = load_ec_point_dp(curve, "vec_QIDk.bin",ctx);
    vec_QIDk = load_ec_point_array(curve, basepath+"vec_QIDk.bin",ctx);
    
    
    
    order = load_bignum_sp(basepath+"order.bin");
    size_t hash_size;
    hash = load_unsigned_char_array(hash_size,basepath+"hash.bin");




    //printf("Enter the level k to sign with: ");
    
    //scanf("%d", &sign_level);
    printf("Signing with level %d\n",sign_level);
    if (sign_level > k || sign_level < 1) {
        fprintf(stderr, "Invalid level for signing.\n");
        return EXIT_FAILURE;
    }
    //if(!vec_QIDk[sign_level])printf("Upto loading\n");
    

    double sign_start_time = get_time_ns();
    
    
    sign_message(message, message_length, sign_level, curve, vec_QIDk, vec_skIDk, order, ctx, hash, &zj, &Rj, &hj);
    

    double sign_end_time = get_time_ns();

    double elapsed_time_sign = (sign_end_time - sign_start_time) / 1e9;  // Convert ns to seconds
    printf("Message Signing phase took: %.9f seconds\n", elapsed_time_sign);
    return EXIT_SUCCESS;
}

int do_verify_hibfss(unsigned char* message, int message_length){
    printf("\n==================== Verification Algorithm ====================\n");
    EC_GROUP *curve = NULL;
    EC_POINT **vec_QIDk = NULL;
    BIGNUM **vec_hIDk = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *PK0 = NULL;
    BIGNUM *order = NULL; 
    unsigned char* hash = new unsigned char[SHA256_DIGEST_LENGTH];
    size_t hash_size;

    // Ensure sign_level is within bounds
    if (sign_level < 1 || sign_level > k) {
        fprintf(stderr, "Error: Invalid sign_level for verification.\n");
        return EXIT_FAILURE;
    }

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
    //vec_QIDk = load_ec_point_dp(curve, "vec_QIDk.bin",ctx);
    vec_QIDk = load_ec_point_array(curve, basepath+"vec_QIDk.bin",ctx);
    //vec_hIDk = load_bignum_dp("vec_hIDk.bin");
    vec_hIDk = load_bignum_array_nullable(basepath+"vec_hIDk.bin");
    PK0 = load_ec_point_sp(curve, basepath+"PK0.bin", ctx);
    order = load_bignum_sp(basepath+"order.bin");
    hash = load_unsigned_char_array(hash_size,basepath+"hash.bin");


    double verify_start_time = get_time_ns();

    verify_signature(message, message_length, sign_level, curve, vec_QIDk, vec_hIDk, PK0, hash, zj, Rj, order, ctx);

    double verify_end_time = get_time_ns();

    double elapsed_time_verify = (verify_end_time - verify_start_time) / 1e9;  // Convert ns to seconds
    printf("Verification phase took: %.9f seconds\n", elapsed_time_verify);
    return EXIT_SUCCESS;

}


// int main(){
//     generate_primitives_hibfss();
//     do_sign_hibfss();
//     do_verify_hibfss();

//     return 1;

// }

}
}
# Main library with the remaining files
add_library(rrc_nr_asn1 STATIC
        common.cpp
        serving_cell.cpp
        ue_cap.cpp
        bwp_cfg.cpp
        radio_bearer_cfg.cpp
        dl_ccch_msg_ies.cpp
        dl_dcch_msg_ies.cpp
        ul_ccch_msg_ies.cpp
        ul_dcch_msg_ies.cpp
        pcch_msg_ies.cpp
        dl_dcch_msg.cpp
        ul_dcch_msg.cpp
        nr_ue_variables.cpp
        pc5_rrc_definitions.cpp
        nr_sidelink_preconf.cpp
        cell_group_config.cpp
        bcch_bch_msg.cpp
        bcch_dl_sch_msg.cpp
        pcch_msg.cpp
        ul_ccch_msg.cpp
        ul_ccch1_msg.cpp
        dl_ccch_msg.cpp
        ho_prep_info.cpp
        meas_cfg.cpp
        meas_timing_cfg.cpp
        rrc_nr.cpp)

# Special library for sys_info.cpp and Modularized_HIBFSS_Schnorr2.cpp
add_library(rrc_nr_special STATIC sys_info.cpp  Modulized_HIBFSS_Schnorr2.cpp Dilithium.cpp CKG.cpp AMF_T_BORG.cpp BSs_T_BORG.cpp AMF_EC_SCHNORR.cpp BS_EC_SCHNORR.cpp AMF_HIBS.cpp BS_HIBS.cpp AMF_ECDSA.cpp BS_ECDSA.cpp crypto_utils.cpp)

# Find OpenSSL (Crypto) if required
find_package(OpenSSL REQUIRED)

# Link special library to required libraries
target_link_libraries(rrc_nr_special PRIVATE OpenSSL::Crypto oqs)

# Link the special library to the main library
target_link_libraries(rrc_nr_asn1 PRIVATE rrc_nr_special asn1_utils)

# Compilation flags for the main library
target_compile_options(rrc_nr_asn1 PRIVATE -Os -fno-exceptions)

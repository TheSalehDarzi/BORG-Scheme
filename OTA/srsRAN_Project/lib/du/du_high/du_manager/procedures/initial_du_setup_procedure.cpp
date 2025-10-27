/*
 *
 * Copyright 2021-2025 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "initial_du_setup_procedure.h"
#include "../converters/f1ap_configuration_helpers.h"
#include "../converters/scheduler_configuration_helpers.h"
#include "../du_cell_manager.h"
#include "srsran/mac/config/mac_config_helpers.h"
#include "srsran/scheduler/config/scheduler_cell_config_validator.h"

using namespace srsran;
using namespace srs_du;

initial_du_setup_procedure::initial_du_setup_procedure(const du_manager_params& params_, du_cell_manager& cell_mng_) :
  params(params_), cell_mng(cell_mng_), logger(srslog::fetch_basic_logger("DU-MNG"))
{
}

void initial_du_setup_procedure::operator()(coro_context<async_task<void>>& ctx)
{
  CORO_BEGIN(ctx);

  // Connect to CU-CP.
  if (not params.f1ap.conn_mng.connect_to_cu_cp()) {
    report_error("Failed to connect DU to CU-CP");
  }

  // Initiate F1 Setup.
  CORO_AWAIT_VALUE(response_msg, start_f1_setup_request());

  // Handle F1 setup result.
  handle_f1_setup_response(response_msg);

  // Configure DU Cells.
  for (unsigned idx = 0; idx < cell_mng.nof_cells(); ++idx) {
    du_cell_index_t           cell_index = to_du_cell_index(idx);
    const du_cell_config&     du_cfg     = cell_mng.get_cell_cfg(cell_index);
    fmt::print("Is this the real life?\n");
    std::vector<byte_buffer>  bcch_msgs  = srs_du::make_asn1_rrc_cell_bcch_dl_sch_msgs(du_cfg);
    std::vector<units::bytes> bcch_msg_payload_lens(bcch_msgs.size());
    for (unsigned i = 0; i < bcch_msgs.size(); ++i) {
      bcch_msg_payload_lens[i] = units::bytes(bcch_msgs[i].length());
    }
    auto                    sched_cfg = srs_du::make_sched_cell_config_req(cell_index, du_cfg, bcch_msg_payload_lens);
    error_type<std::string> result =
        config_validators::validate_sched_cell_configuration_request_message(sched_cfg, params.mac.sched_cfg);
    if (not result.has_value()) {
      report_error("Invalid cell={} configuration. Cause: {}", fmt::underlying(cell_index), result.error());
    }
    params.mac.cell_mng.add_cell(make_mac_cell_config(cell_index, du_cfg, std::move(bcch_msgs), sched_cfg));
  }

  // Activate DU Cells.
  params.mac.cell_mng.get_cell_controller(to_du_cell_index(0)).start();
  fmt::print("Okay upto this\n");
  //mirza:start
//   std::thread sib1_rotator_thread([this, du_cfg = cell_mng.get_cell_cfg(to_du_cell_index(0))]() mutable {
//     std::vector<byte_buffer> sib1_variants;
//     fmt::print("Okay here\n");
    
//     for (int i = 0; i < 5; ++i) {
//       // Option 1: Use different `du_cell_config` inputs to create different SIB1s
//       du_cell_config modified_cfg = du_cfg;
//       //modified_cfg.cell_barred = false; // or change plmn, t300, etc.
//       fmt::print("Okay in for loop here\n");
//       auto bcch_msgs = srs_du::make_asn1_rrc_cell_bcch_dl_sch_msgs(modified_cfg);

//       // We want only the first message (SIB1)
//       srsran_assert(!bcch_msgs.empty(), "No BCCH messages generated");
//       fmt::print("Okay here end of for loop\n");
//       sib1_variants.push_back(std::move(bcch_msgs[0]));
    
//     }
//     du_cell_index_t cell_index = to_du_cell_index(0);
//     size_t sib_idx = 0;
//     int loop_counter = 5;
//     while (loop_counter--) {
//       const auto& sib = sib1_variants[sib_idx];
//       this->params.mac.cell_mng.update_bcch_payload(cell_index, sib);
//       fmt::print("✅ Updated SIB1 to variant {}\n", sib_idx);
//       sib_idx = (sib_idx + 1) % sib1_variants.size();
//       std::this_thread::sleep_for(std::chrono::seconds(5));
//     }

// });
//mirza:end

//mirza:start
  // std::vector<byte_buffer> sib1_variants;
  // fmt::print("Okay here\n");

  // for (int i = 0; i < 3; ++i) {
  //   // Option 1: Use different `du_cell_config` inputs to create different SIB1s
  //   du_cell_config modified_cfg = cell_mng.get_cell_cfg(to_du_cell_index(0));
  //   modified_cfg.tac = 6+i; // or change plmn, t300, etc.
  //   fmt::print("Okay in for loop here\n");
  //   auto bcch_msgs = srs_du::make_asn1_rrc_cell_bcch_dl_sch_msgs(modified_cfg);

  //   // We want only the first message (SIB1)
  //   srsran_assert(!bcch_msgs.empty(), "No BCCH messages generated");
  //   fmt::print("Okay here end of for loop\n");
  //   sib1_variants.push_back(std::move(bcch_msgs[0]));

  // }
  // du_cell_index_t cell_index = to_du_cell_index(0);
  // size_t sib_idx = 0;
  // int loop_counter = 5;
  // while (loop_counter--) {
  //   const auto& sib = sib1_variants[sib_idx];
  //   this->params.mac.cell_mng.update_bcch_payload(cell_index, sib);
  //   fmt::print("✅ Updated SIB1 to variant {}\n", sib_idx);
  //   sib_idx = (sib_idx + 1) % sib1_variants.size();
  //   //std::this_thread::sleep_for(std::chrono::seconds(5));
  // }
//mirza:end

  // params.mac.cell_mng.get_cell_controller(to_du_cell_index(0)).stop();

  // fmt::print("nof cells {}\n",cell_mng.nof_cells());
  // for (unsigned idx = 0; idx < cell_mng.nof_cells(); ++idx) {
  //   du_cell_index_t           cell_index = to_du_cell_index(idx);
  //   fmt::print("Life was good\n");
  //   params.mac.cell_mng.remove_cell(cell_index);
  // }

  

  //{
  //mirza:start
  // Handle F1 setup result.
  //handle_f1_setup_response(response_msg);

  // Configure DU Cells.
  // for (unsigned idx = 0; idx < cell_mng.nof_cells(); ++idx) {
  //   du_cell_index_t           cell_index = to_du_cell_index(idx);
  //   const du_cell_config&     du_cfg     = cell_mng.get_cell_cfg(cell_index);
  //   fmt::print("Is this the real life?\n");
  //   std::vector<byte_buffer>  bcch_msgs  = srs_du::make_asn1_rrc_cell_bcch_dl_sch_msgs(du_cfg);
  //   std::vector<units::bytes> bcch_msg_payload_lens(bcch_msgs.size());
  //   for (unsigned i = 0; i < bcch_msgs.size(); ++i) {
  //     bcch_msg_payload_lens[i] = units::bytes(bcch_msgs[i].length());
  //   }
  //   auto                    sched_cfg = srs_du::make_sched_cell_config_req(cell_index, du_cfg, bcch_msg_payload_lens);
  //   error_type<std::string> result =
  //       config_validators::validate_sched_cell_configuration_request_message(sched_cfg, params.mac.sched_cfg);
  //   if (not result.has_value()) {
  //     report_error("Invalid cell={} configuration. Cause: {}", fmt::underlying(cell_index), result.error());
  //   }
  //   fmt::print("IS THIS OK?\n");
  //   params.mac.cell_mng.add_cell(make_mac_cell_config(cell_index, du_cfg, std::move(bcch_msgs), sched_cfg));
  //   fmt::print("WHAT ABOUT THIS?\n");
  // }

  // // Activate DU Cells.
  // params.mac.cell_mng.get_cell_controller(to_du_cell_index(0)).start();

  // }
  //mirza:end


  CORO_RETURN();
}

async_task<f1_setup_response_message> initial_du_setup_procedure::start_f1_setup_request()
{
  // Prepare request to send to F1.
  f1_setup_request_message request_msg = {};

  std::vector<std::string> sib1_jsons;
  fill_f1_setup_request(request_msg, params.ran, &sib1_jsons);

  // Log RRC ASN.1 SIB1 json.
  for (unsigned i = 0; i != sib1_jsons.size(); ++i) {
    logger.info(request_msg.served_cells[i].du_sys_info.packed_sib1.begin(),
                request_msg.served_cells[i].du_sys_info.packed_sib1.end(),
                "SIB1 cell={}: {}",
                fmt::underlying(to_du_cell_index(i)),
                sib1_jsons[i]);
  }

  // Initiate F1 Setup Request.
  return params.f1ap.conn_mng.handle_f1_setup_request(request_msg);
}

void initial_du_setup_procedure::handle_f1_setup_response(const f1_setup_response_message& resp)
{
  if (resp.result != f1_setup_response_message::result_code::success) {
    std::string cause;
    switch (resp.result) {
      case f1_setup_response_message::result_code::f1_setup_failure:
        cause = "CU-CP responded with \"F1 Setup Failure\"";
        if (resp.f1_setup_failure_cause != "unspecified") {
          cause += fmt::format(" with F1AP cause \"{}\"", resp.f1_setup_failure_cause);
        }
        break;
      case f1_setup_response_message::result_code::invalid_response:
        cause = "CU-CP response to F1 Setup Request is invalid";
        break;
      case f1_setup_response_message::result_code::timeout:
        cause = "CU-CP did not respond to F1 Setup Request";
        break;
      case f1_setup_response_message::result_code::proc_failure:
        cause = "DU failed to run F1 Setup Procedure";
      default:
        report_fatal_error("Invalid F1 Setup Response");
    }
    report_error("F1 Setup failed. Cause: {}", cause);
  }
}

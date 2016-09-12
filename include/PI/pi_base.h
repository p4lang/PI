/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

//! @file

#ifndef PI_INC_PI_PI_BASE_H_
#define PI_INC_PI_PI_BASE_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

//! 0 is always an invalid P4 id
#define PI_INVALID_ID 0

//! The different config types which can be parsed to create a p4info object.
typedef enum {
  PI_CONFIG_TYPE_NONE = 0,  // for testing
  PI_CONFIG_TYPE_BMV2_JSON,
  PI_CONFIG_TYPE_NATIVE_JSON
} pi_config_type_t;

//! Possible status codes for PI calls. Values above 1000 are reserved for
//! target backends.
typedef enum {
  PI_STATUS_SUCCESS = 0,
  PI_STATUS_INVALID_CONFIG_TYPE,
  PI_STATUS_INVALID_INIT_EXTRA_PARAM,
  PI_STATUS_MISSING_INIT_EXTRA_PARAM,
  PI_STATUS_TARGET_TRANSPORT_ERROR,
  PI_STATUS_RPC_CONNECT_ERROR,
  PI_STATUS_RPC_TRANSPORT_ERROR,
  PI_STATUS_RPC_NOT_INIT,
  PI_STATUS_NOTIF_CONNECT_ERROR,
  PI_STATUS_NOTIF_BIND_ERROR,
  PI_STATUS_CONFIG_READER_ERROR,
  PI_STATUS_BUFFER_ERROR,
  PI_STATUS_NETV_INVALID_SIZE,
  PI_STATUS_NETV_INVALID_OBJ_ID,
  PI_STATUS_DEV_OUT_OF_RANGE,
  PI_STATUS_DEV_ALREADY_ASSIGNED,
  PI_STATUS_DEV_NOT_ASSIGNED,

  PI_STATUS_INVALID_ENTRY_PROPERTY,
  PI_STATUS_INVALID_ENTRY_TYPE,
  PI_STATUS_UNSUPPORTED_MATCH_TYPE,
  PI_STATUS_CONST_DEFAULT_ACTION,
  PI_STATUS_NOT_A_DIRECT_RES_OF_TABLE,
  // TODO(antonin): remove now that we have PI_STATUS_TARGET_ERROR?
  PI_STATUS_INVALID_TABLE_OPERATION,

  PI_STATUS_METER_SPEC_NOT_SET,

  PI_STATUS_COUNTER_IS_DIRECT,
  PI_STATUS_COUNTER_IS_NOT_DIRECT,
  PI_STATUS_METER_IS_DIRECT,
  PI_STATUS_METER_IS_NOT_DIRECT,

  PI_STATUS_OUT_OF_BOUND_IDX,

  PI_STATUS_INVALID_RES_TYPE_ID,

  PI_STATUS_LEARN_NO_MATCHING_CB,
  PI_STATUS_PACKETIN_NO_CB,
  PI_STATUS_PACKETOUT_SEND_ERROR,

  PI_STATUS_NOT_IMPLEMENTED_BY_TARGET,

  //! everything above 1000 is reserved for targets
  PI_STATUS_TARGET_ERROR = 1000
} pi_status_t;

//! An id for any P4 object.
typedef uint32_t pi_p4_id_t;

//! Device identifier.
typedef uint16_t pi_dev_id_t;

//! Identifies a device plus a pipe (or set of pipes?) within device.
typedef struct {
  pi_dev_id_t dev_id;
  uint16_t dev_pipe_mask;
} pi_dev_tgt_t;

//! Identifies a client sessions.
typedef uint32_t pi_session_handle_t;

//! Forward declaration of p4info (P4 config)
typedef struct pi_p4info_s pi_p4info_t;

#define PI_ACTION_ID 0x01
#define PI_TABLE_ID 0x02
#define PI_ACTION_PARAM_ID 0x03
#define PI_FIELD_ID 0x04
#define PI_FIELD_LIST_ID 0x05

#define PI_ACT_PROF_ID 0x11

#define PI_COUNTER_ID 0x12
#define PI_METER_ID 0x13

#define PI_RES_TYPE_MAX 0x100

typedef size_t pi_res_type_id_t;

// TODO(antonin): make inline?
bool pi_is_action_id(pi_p4_id_t id);
bool pi_is_table_id(pi_p4_id_t id);
bool pi_is_action_param_id(pi_p4_id_t id);
bool pi_is_field_id(pi_p4_id_t id);

bool pi_is_act_prof_id(pi_p4_id_t id);

bool pi_is_counter_id(pi_p4_id_t id);
bool pi_is_meter_id(pi_p4_id_t id);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_BASE_H_

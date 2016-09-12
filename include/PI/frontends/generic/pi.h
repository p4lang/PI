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

#ifndef PI_INC_PI_FRONTENDS_GENERIC_PI_H_
#define PI_INC_PI_FRONTENDS_GENERIC_PI_H_

#include "PI/pi_base.h"
#include "PI/pi_tables.h"

typedef uint16_t pi_prefix_length_t;

////////// MATCH KEY //////////

//! Allocate a match jey object for a given table
pi_status_t pi_match_key_allocate(const pi_p4info_t *p4info,
                                  const pi_p4_id_t table_id,
                                  pi_match_key_t **key);

//! Reset state of a match key. This function does not perform any memory
//! allocation.
pi_status_t pi_match_key_init(pi_match_key_t *key);

pi_status_t pi_match_key_exact_set(pi_match_key_t *key, const pi_netv_t *fv);
pi_status_t pi_match_key_exact_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                   pi_netv_t *fv);

pi_status_t pi_match_key_lpm_set(pi_match_key_t *key, const pi_netv_t *fv,
                                 const pi_prefix_length_t prefix_length);
pi_status_t pi_match_key_lpm_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                 pi_netv_t *fv,
                                 pi_prefix_length_t *prefix_length);

pi_status_t pi_match_key_ternary_set(pi_match_key_t *key, const pi_netv_t *fv,
                                     const pi_netv_t *mask);
pi_status_t pi_match_key_ternary_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                     pi_netv_t *fv, pi_netv_t *mask);

pi_status_t pi_match_key_range_set(pi_match_key_t *key, const pi_netv_t *start,
                                   const pi_netv_t *end);
pi_status_t pi_match_key_range_get(const pi_match_key_t *key, pi_p4_id_t fid,
                                   pi_netv_t *start, pi_netv_t *end);

//! Destroy match key allocated with pi_match_key_allocate
pi_status_t pi_match_key_destroy(pi_match_key_t *key);

////////// ACTION DATA //////////

//! Allocate an action data object
pi_status_t pi_action_data_allocate(const pi_p4info_t *p4info,
                                    const pi_p4_id_t action_id,
                                    pi_action_data_t **adata);

//! Reset state of an action data. This function does not perform any memory
//! allocation.
pi_status_t pi_action_data_init(pi_action_data_t *adata);

pi_p4_id_t pi_action_data_action_id_get(const pi_action_data_t *adata);

pi_status_t pi_action_data_arg_set(pi_action_data_t *adata,
                                   const pi_netv_t *argv);
pi_status_t pi_action_data_arg_get(const pi_action_data_t *adata,
                                   pi_p4_id_t pid, pi_netv_t *argv);

//! Destroy action data allocated with pi_action_data_allocate
pi_status_t pi_action_data_destroy(pi_action_data_t *action_data);

#endif  // PI_INC_PI_FRONTENDS_GENERIC_PI_H_

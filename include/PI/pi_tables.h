/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PI_INC_PI_PI_TABLES_H_
#define PI_INC_PI_PI_TABLES_H_

#include "pi_base.h"
#include "pi_value.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  PI_ENTRY_PROPERTY_TYPE_PRIORITY = 0,
  PI_ENTRY_PROPERTY_TYPE_TTL,
  PI_ENTRY_PROPERTY_TYPE_END
} pi_entry_property_type_t;

// TODO(antonin): hide this?
struct pi_entry_properties_s {
  uint32_t valid_properties;
  uint32_t priority;
  uint32_t ttl;
};

typedef struct pi_entry_properties_s pi_entry_properties_t;

void pi_entry_properties_clear(pi_entry_properties_t *properties);
// for now both properties are uint32_t, we'll see if we need to change it in
// the future
pi_status_t pi_entry_properties_set(pi_entry_properties_t *properties,
                                    pi_entry_property_type_t property_type,
                                    uint32_t property_value);
                                    /* const pi_value_t *property_value); */
bool pi_entry_properties_is_set(const pi_entry_properties_t *properties,
                                pi_entry_property_type_t property_type);

typedef uint64_t pi_entry_handle_t;

typedef uint64_t pi_indirect_handle_t;

typedef struct pi_match_key_s pi_match_key_t;

typedef struct pi_action_data_s pi_action_data_t;

typedef int pi_res_config_t;

typedef enum {
  PI_ACTION_ENTRY_TYPE_NONE = 0,
  PI_ACTION_ENTRY_TYPE_DATA,
  PI_ACTION_ENTRY_TYPE_INDIRECT,
} pi_action_entry_type_t;

typedef struct {
  pi_action_entry_type_t entry_type;
  union {
    pi_action_data_t *action_data;
    pi_indirect_handle_t indirect_handle;
  } entry;
  const pi_entry_properties_t *entry_properties;
  const pi_res_config_t *direct_res_config;  /* not defined yet */
} pi_table_entry_t;

typedef struct {
  pi_match_key_t *match_key;
  pi_table_entry_t entry;
} pi_table_ma_entry_t;

/* trying to add an entry that already exists returns an error, unless the */
/* ‘overwrite’ flag is set */
pi_status_t pi_table_entry_add(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt,
                               pi_p4_id_t table_id,
                               const pi_match_key_t *match_key,
                               const pi_table_entry_t *table_entry,
                               int overwrite,
                               pi_entry_handle_t *entry_handle);

/* no need for a "clear" method, would not match default action definition */
pi_status_t pi_table_default_action_set(pi_session_handle_t session_handle,
                                        pi_dev_tgt_t dev_tgt,
                                        pi_p4_id_t table_id,
                                        const pi_table_entry_t *table_entry);

pi_status_t pi_table_default_action_get(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id,
                                        pi_p4_id_t table_id,
                                        pi_table_entry_t *table_entry);

pi_status_t pi_table_default_action_done(pi_session_handle_t session_handle,
                                         pi_table_entry_t *table_entry);

pi_status_t pi_table_entry_delete(pi_session_handle_t session_handle,
                                  pi_dev_id_t dev_id,
                                  pi_p4_id_t table_id,
                                  pi_entry_handle_t entry_handle);

/* should we just get rid of this and use the above entry_add with overwrite? */
pi_status_t pi_table_entry_modify(pi_session_handle_t session_handle,
                                  pi_dev_id_t dev_id,
                                  pi_p4_id_t table_id,
                                  pi_entry_handle_t entry_handle,
                                  const pi_table_entry_t *table_entry);

typedef struct pi_table_fetch_res_s pi_table_fetch_res_t;

pi_status_t pi_table_entries_fetch(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id,
                                   pi_p4_id_t table_id,
                                   pi_table_fetch_res_t **res);

pi_status_t pi_table_entries_fetch_done(pi_session_handle_t session_handle,
                                        pi_table_fetch_res_t *res);

size_t pi_table_entries_num(pi_table_fetch_res_t *res);

size_t pi_table_entries_next(pi_table_fetch_res_t *res,
                             pi_table_ma_entry_t *entry,
                             pi_entry_handle_t *entry_handle);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_TABLES_H_

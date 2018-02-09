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

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

//! @file

#ifndef PI_INC_PI_PI_TABLES_H_
#define PI_INC_PI_PI_TABLES_H_

#include "pi_base.h"
#include "pi_value.h"

#ifdef __cplusplus
extern "C" {
#endif

//! Possible properties for a table entry
typedef enum {
  //! Entry TTL, for entry ageing
  PI_ENTRY_PROPERTY_TYPE_TTL,
  PI_ENTRY_PROPERTY_TYPE_END
} pi_entry_property_type_t;

// TODO(antonin): hide this?
//! List of properties for a new entry, will probably be improved in the future.
struct pi_entry_properties_s {
  uint32_t valid_properties;
  uint32_t ttl;
};

typedef struct pi_entry_properties_s pi_entry_properties_t;

//! Clear all properties.
void pi_entry_properties_clear(pi_entry_properties_t *properties);
// for now both properties are uint32_t, we'll see if we need to change it in
// the future
//! Set a property.
pi_status_t pi_entry_properties_set(pi_entry_properties_t *properties,
                                    pi_entry_property_type_t property_type,
                                    uint32_t property_value);
/* const pi_value_t *property_value); */
//! Test if a property is set.
bool pi_entry_properties_is_set(const pi_entry_properties_t *properties,
                                pi_entry_property_type_t property_type);

typedef uint64_t pi_entry_handle_t;

typedef uint64_t pi_indirect_handle_t;

//! Forward declaration for a match key.
typedef struct pi_match_key_s pi_match_key_t;

//! Forward declaration for action data.
typedef struct pi_action_data_s pi_action_data_t;

//! Configuration of a direct resource attached to an entry. We use a generic
//! void* pointer for the config. Based on the \p res_id, each target backend
//! will be able to parse this config.
typedef struct {
  pi_p4_id_t res_id;
  void *config;
} pi_direct_res_config_one_t;

//! All the direct resource configurations for a given table entry.
typedef struct {
  size_t num_configs;
  pi_direct_res_config_one_t *configs;
} pi_direct_res_config_t;

//! An entry can either be direct (regular table), or indirect if it has a
//! specific implementation (e.g. action profile).
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
  const pi_direct_res_config_t *direct_res_config;
} pi_table_entry_t;

//! this is used for iterating over entries after a fetch operation
typedef struct {
  pi_match_key_t *match_key;
  pi_table_entry_t entry;
} pi_table_ma_entry_t;

//! Adds an entry to a table. Trying to add an entry that already exists should
//! return an error, unless the \p overwrite flag is set.
pi_status_t pi_table_entry_add(pi_session_handle_t session_handle,
                               pi_dev_tgt_t dev_tgt, pi_p4_id_t table_id,
                               const pi_match_key_t *match_key,
                               const pi_table_entry_t *table_entry,
                               int overwrite, pi_entry_handle_t *entry_handle);

//! Sets the default entry for a table. Should return an error if the default
//! entry was statically configured and set as const in the P4 program.
pi_status_t pi_table_default_action_set(pi_session_handle_t session_handle,
                                        pi_dev_tgt_t dev_tgt,
                                        pi_p4_id_t table_id,
                                        const pi_table_entry_t *table_entry);

//! Resets the default entry for a table, as previously set with
//! pi_table_default_action_set, to the original default action (as specified in
//! the P4 program).
pi_status_t pi_table_default_action_reset(pi_session_handle_t session_handle,
                                          pi_dev_tgt_t dev_tgt,
                                          pi_p4_id_t table_id);

//! Retrieve the default entry for a table.
pi_status_t pi_table_default_action_get(pi_session_handle_t session_handle,
                                        pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                        pi_table_entry_t *table_entry);

//! Need to be called after pi_table_default_action_get, once you wish the
//! memory to be released.
pi_status_t pi_table_default_action_done(pi_session_handle_t session_handle,
                                         pi_table_entry_t *table_entry);

//! Delete an entry from a table using the entry handle. Should return an error
//! if entry does not exist.
pi_status_t pi_table_entry_delete(pi_session_handle_t session_handle,
                                  pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                  pi_entry_handle_t entry_handle);

//! Delete an entry from a table using the match key. Should return an error
//! if entry does not exist.
pi_status_t pi_table_entry_delete_wkey(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                       const pi_match_key_t *match_key);

//! Modify an existing entry using the entry handle. Should return an error if
//! entry does not exist.
pi_status_t pi_table_entry_modify(pi_session_handle_t session_handle,
                                  pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                  pi_entry_handle_t entry_handle,
                                  const pi_table_entry_t *table_entry);

//! Modify an existing entry using the match key. Should return an error if
//! entry does not exist.
pi_status_t pi_table_entry_modify_wkey(pi_session_handle_t session_handle,
                                       pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                       const pi_match_key_t *match_key,
                                       const pi_table_entry_t *table_entry);

typedef struct pi_table_fetch_res_s pi_table_fetch_res_t;

//! Retrieve all entries in table as one big blob.
pi_status_t pi_table_entries_fetch(pi_session_handle_t session_handle,
                                   pi_dev_id_t dev_id, pi_p4_id_t table_id,
                                   pi_table_fetch_res_t **res);

//! Need to be called after a pi_table_entries_fetch, once you wish the memory
//! to be released.
pi_status_t pi_table_entries_fetch_done(pi_session_handle_t session_handle,
                                        pi_table_fetch_res_t *res);

//! Returns the number of entries obtained with pi_table_entries_fetch.
size_t pi_table_entries_num(pi_table_fetch_res_t *res);

//! Iterates through entries retrieved with pi_table_entries_fetch.
size_t pi_table_entries_next(pi_table_fetch_res_t *res,
                             pi_table_ma_entry_t *entry,
                             pi_entry_handle_t *entry_handle);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_TABLES_H_

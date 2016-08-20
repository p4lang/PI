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

#ifndef PI_INC_PI_PI_H_
#define PI_INC_PI_PI_H_

#include "pi_base.h"
#include "pi_tables.h"
#include "pi_act_prof.h"

#ifdef __cplusplus
extern "C" {
#endif

// returns NULL if device not assigned
const pi_p4info_t *pi_get_device_p4info(pi_dev_id_t dev_id);

pi_status_t pi_init(size_t max_devices, char *rpc_addr);

typedef struct {
  int end_of_extras;
  const char *key;
  const char *v;
} pi_assign_extra_t;

pi_status_t pi_assign_device(pi_dev_id_t dev_id, const pi_p4info_t *p4info,
                             pi_assign_extra_t *extra);

pi_status_t pi_remove_device(pi_dev_id_t dev_id);

pi_status_t pi_session_init(pi_session_handle_t *session_handle);

pi_status_t pi_session_cleanup(pi_session_handle_t session_handle);

pi_status_t pi_destroy();

// TODO(antonin): move this to pi_tables?
// When adding a table entry, the configuration for direct resources associated
// with the entry can be provided. The config is then passed as a generic void *
// pointer. For the sake of the messaging system, we need a way to seriralize /
// de-serialize the config, thus the need for these:
// size when serialized
typedef size_t (*PIDirectResMsgSizeFn)(const void *config);
// emit function for serialization
typedef size_t (*PIDirectResEmitFn)(char *dst, const void *config);
// retrieve function for de-serialization
typedef size_t (*PIDirectResRetrieveFn)(const char *src, void *config);
// size_of is the size of memory blob required by retrieve function, alignment
// is guaranteed to be maximum for the architecture (e.g. 16 bytes for x86_64)
pi_status_t pi_direct_res_register(pi_res_type_id_t res_type,
                                   PIDirectResMsgSizeFn msg_size_fn,
                                   PIDirectResEmitFn emit_fn, size_t size_of,
                                   PIDirectResRetrieveFn retrieve_fn);

// set ptr to NULL if not interested
pi_status_t pi_direct_res_get_fns(pi_res_type_id_t res_type,
                                  PIDirectResMsgSizeFn *msg_size_fn,
                                  PIDirectResEmitFn *emit_fn, size_t *size_of,
                                  PIDirectResRetrieveFn *retrieve_fn);

#ifdef __cplusplus
}
#endif

#endif  // PI_INC_PI_PI_H_

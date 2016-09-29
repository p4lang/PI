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

#include "pd/pd_counters.h"
#include "pd_utils.h"

#include <PI/pi.h>
#include <PI/pi_counter.h>

#include <stdlib.h>

__attribute__ ((unused))
static void convert_to_counter_data(const pi_p4info_t *p4info,
                                    pi_p4_id_t counter_id,
                                    const p4_pd_counter_value_t *counter_value,
                                    pi_counter_data_t *counter_data) {
  pi_p4info_counter_unit_t counter_unit =
      pi_p4info_counter_get_unit(p4info, counter_id);
  switch (counter_unit) {
    case PI_P4INFO_COUNTER_UNIT_BYTES:
      counter_data->valid = PI_COUNTER_UNIT_BYTES;
      break;
    case PI_P4INFO_COUNTER_UNIT_PACKETS:
      counter_data->valid = PI_COUNTER_UNIT_PACKETS;
      break;
    case PI_P4INFO_COUNTER_UNIT_BOTH:
      counter_data->valid = PI_COUNTER_UNIT_BYTES | PI_COUNTER_UNIT_PACKETS;
      break;
  }
  if (counter_data->valid & PI_COUNTER_UNIT_BYTES)
    counter_data->bytes = counter_value->bytes;
  if (counter_data->valid & PI_COUNTER_UNIT_PACKETS)
    counter_data->packets = counter_value->packets;
}

typedef struct {
  void *pd_cookie;
  p4_pd_stat_sync_cb pd_cb;
} hw_sync_cb_data_t;

__attribute__ ((unused))
static void hw_sync_cb_wrapper(pi_dev_id_t dev_id, pi_p4_id_t counter_id,
                               void *cb_cookie) {
  hw_sync_cb_data_t *cookie = (hw_sync_cb_data_t *) cb_cookie;
  cookie->pd_cb(dev_id, cookie->pd_cookie);
  free(cookie);
}

//:: for ca_name, ca in counter_arrays.items():
//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "p4_pd_dev_target_t dev_tgt"]
//::   if ca.is_direct:
//::     params += ["p4_pd_entry_hdl_t entry_hdl"]
//::   else:
//::     params += ["int index"]
//::   #endif
//::   params += ["int flags"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + "counter_read_" + ca_name
p4_pd_counter_value_t
${name}
(
 ${param_str}
) {
  p4_pd_counter_value_t counter_value = {0u, 0u};
  pi_status_t rc;
  pi_counter_data_t counter_data;
  // TODO(antonin)
  int new_flags = flags;
//::   if ca.is_direct:
  rc = pi_counter_read_direct(sess_hdl, convert_dev_tgt(dev_tgt), ${ca.id_},
                              entry_hdl, new_flags, &counter_data);
//::   else:
  rc = pi_counter_read(sess_hdl, convert_dev_tgt(dev_tgt), ${ca.id_},
                       index, new_flags, &counter_data);
//::   #endif
  if (rc != PI_STATUS_SUCCESS) return counter_value;
  if (counter_data.valid & PI_COUNTER_UNIT_PACKETS)
    counter_value.packets = counter_data.packets;
  if (counter_data.valid & PI_COUNTER_UNIT_BYTES)
    counter_value.bytes = counter_data.bytes;
  return counter_value;
}

//::   params = ["p4_pd_sess_hdl_t sess_hdl",
//::             "p4_pd_dev_target_t dev_tgt"]
//::   if ca.is_direct:
//::     params += ["p4_pd_entry_hdl_t entry_hdl"]
//::   else:
//::     params += ["int index"]
//::   #endif
//::   params += ["p4_pd_counter_value_t counter_value"]
//::   param_str = ",\n ".join(params)
//::   name = pd_prefix + "counter_write_" + ca_name
p4_pd_status_t
${name}
(
 ${param_str}
) {
  const pi_p4info_t *p4info = pi_get_device_p4info(dev_tgt.device_id);
  pi_counter_data_t counter_data;
  convert_to_counter_data(p4info, ${ca.id_}, &counter_value, &counter_data);
  pi_status_t rc;

//::   if ca.is_direct:
  rc = pi_counter_write_direct(sess_hdl, convert_dev_tgt(dev_tgt), ${ca.id_},
                               entry_hdl, &counter_data);
//::   else:
  rc = pi_counter_write(sess_hdl, convert_dev_tgt(dev_tgt), ${ca.id_},
                        index, &counter_data);
//::   #endif
  return rc;
}

//::   name = pd_prefix + "counter_hw_sync_" + ca_name
p4_pd_status_t
${name}
(
 p4_pd_sess_hdl_t sess_hdl,
 p4_pd_dev_target_t dev_tgt,
 p4_pd_stat_sync_cb cb_fn,
 void *cb_cookie
) {
  hw_sync_cb_data_t *data = malloc(sizeof(hw_sync_cb_data_t));
  data->pd_cb = cb_fn;
  data->pd_cookie = cb_cookie;
  return pi_counter_hw_sync(sess_hdl, convert_dev_tgt(dev_tgt), ${ca.id_},
                            hw_sync_cb_wrapper, data);
}

//:: #endfor

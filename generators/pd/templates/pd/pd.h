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

#ifndef _P4_PD_H_
#define _P4_PD_H_

#include "pd_tables.h"
#include "pd_counters.h"
#include "pd_meters.h"

#ifdef __cplusplus
extern "C" {
#endif

p4_pd_status_t ${pd_prefix}init(void);

p4_pd_status_t ${pd_prefix}assign_device(int dev_id,
                                         const char *config_path);
                                         /* const pd_assign_extra_t *extra); */

p4_pd_status_t ${pd_prefix}remove_device(int dev_id);

#ifdef __cplusplus
}
#endif

#endif

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

#ifndef PI_SRC_P4INFO_INT_H_
#define PI_SRC_P4INFO_INT_H_

#include "p4info/actions_int.h"
#include "p4info/tables_int.h"
#include "p4info/fields_int.h"
#include "p4info/act_profs_int.h"
#include "p4info/counters_int.h"
#include "p4info/meters_int.h"
#include "p4info/field_list_int.h"

p4info_common_t *pi_p4info_get_common(pi_p4info_t *p4info, pi_p4_id_t id);

#endif  // PI_SRC_P4INFO_INT_H_

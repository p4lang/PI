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

#ifndef PI_SRC_P4INFO_P4INFO_STRUCT_H_
#define PI_SRC_P4INFO_P4INFO_STRUCT_H_

#include <stddef.h>

#include <Judy.h>

struct pi_p4info_s {
  size_t num_actions;
  struct _action_data_s *actions;
  Pvoid_t action_name_map;

  size_t num_tables;
  struct _table_data_s *tables;
  Pvoid_t table_name_map;

  size_t num_fields;
  struct _field_data_s *fields;
  Pvoid_t field_name_map;

  size_t num_act_profs;
  struct _act_prof_data_s *act_profs;
  Pvoid_t act_prof_name_map;
};

#endif // PI_SRC_P4INFO_P4INFO_STRUCT_H_

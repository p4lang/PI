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

#ifndef PI_CLI_TABLE_INDIRECT_TABLE_INDIRECT_COMMON_H_
#define PI_CLI_TABLE_INDIRECT_TABLE_INDIRECT_COMMON_H_

#include "error_codes.h"

#include "PI/pi.h"

extern const pi_p4info_t *p4info_curr;
extern pi_dev_tgt_t dev_tgt;
extern pi_session_handle_t sess;

char *complete_act_prof(const char *text, int state);
char *complete_act_prof_and_action(const char *text, int state);

#endif  // PI_CLI_TABLE_INDIRECT_TABLE_INDIRECT_COMMON_H_

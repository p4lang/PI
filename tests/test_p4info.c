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

#include "PI/int/pi_int.h"
#include "PI/p4info.h"
#include "p4info_int.h"
#include "read_file.h"

#include "utils.h"

#include "unity/unity_fixture.h"

#include <Judy.h>
#include <string.h>

#define DEFAULT_TABLE_SIZE 1024
#define DEFAULT_TABLE_IS_CONST false
#define DEFAULT_TABLE_IDLE_TIMEOUT false

static pi_p4info_t *p4info;

TEST_GROUP(P4Info);

TEST_SETUP(P4Info) { pi_add_config(NULL, PI_CONFIG_TYPE_NONE, &p4info); }

TEST_TEAR_DOWN(P4Info) { pi_destroy_config(p4info); }

typedef struct {
  pi_p4_id_t id;
  char *name;
  size_t num_params;
} adata_t;

TEST(P4Info, Actions) {
  const size_t num_actions = 2;
  const adata_t adata_0 = {pi_make_action_id(0), "a0", 2};
  const adata_t adata_1 = {pi_make_action_id(1), "a1", 0};

  const char *const param_names[2] = {"p0_0", "p0_1"};
  const size_t param_bws[2] = {18, 3};
  const size_t param_offsets[2] = {0, (param_bws[0] + 7) / 8};

  pi_p4info_action_init(p4info, num_actions);

  pi_p4info_action_add(p4info, adata_0.id, adata_0.name, adata_0.num_params);
  pi_p4info_action_add(p4info, adata_1.id, adata_1.name, adata_1.num_params);

  pi_p4_id_t param_0_0 = 0;
  pi_p4_id_t param_0_1 = 1;

  pi_p4info_action_add_param(p4info, adata_0.id, param_0_0, param_names[0],
                             param_bws[0]);
  pi_p4info_action_add_param(p4info, adata_0.id, param_0_1, param_names[1],
                             param_bws[1]);

  TEST_ASSERT_EQUAL_UINT(adata_0.id,
                         pi_p4info_action_id_from_name(p4info, adata_0.name));
  TEST_ASSERT_EQUAL_UINT(adata_1.id,
                         pi_p4info_action_id_from_name(p4info, adata_1.name));

  TEST_ASSERT_EQUAL_STRING(adata_0.name,
                           pi_p4info_action_name_from_id(p4info, adata_0.id));
  TEST_ASSERT_EQUAL_STRING(adata_1.name,
                           pi_p4info_action_name_from_id(p4info, adata_1.id));

  TEST_ASSERT_EQUAL_UINT(adata_0.num_params,
                         pi_p4info_action_num_params(p4info, adata_0.id));
  TEST_ASSERT_EQUAL_UINT(adata_1.num_params,
                         pi_p4info_action_num_params(p4info, adata_1.id));

  TEST_ASSERT_EQUAL_UINT(param_0_0, pi_p4info_action_param_id_from_name(
                                        p4info, adata_0.id, param_names[0]));
  TEST_ASSERT_EQUAL_UINT(param_0_1, pi_p4info_action_param_id_from_name(
                                        p4info, adata_0.id, param_names[1]));

  TEST_ASSERT_EQUAL_STRING(param_names[0], pi_p4info_action_param_name_from_id(
                                               p4info, adata_0.id, param_0_0));
  TEST_ASSERT_EQUAL_STRING(param_names[1], pi_p4info_action_param_name_from_id(
                                               p4info, adata_0.id, param_0_1));

  TEST_ASSERT_EQUAL_UINT(param_bws[0], pi_p4info_action_param_bitwidth(
                                           p4info, adata_0.id, param_0_0));
  TEST_ASSERT_EQUAL_UINT(param_bws[1], pi_p4info_action_param_bitwidth(
                                           p4info, adata_0.id, param_0_1));

  TEST_ASSERT_EQUAL_UINT(param_offsets[0], pi_p4info_action_param_offset(
                                               p4info, adata_0.id, param_0_0));
  TEST_ASSERT_EQUAL_UINT(param_offsets[1], pi_p4info_action_param_offset(
                                               p4info, adata_0.id, param_0_1));
}

TEST(P4Info, ActionsInvalidId) {
  const size_t num_actions = 1;
  pi_p4info_action_init(p4info, num_actions);
  TEST_ASSERT_EQUAL_UINT(PI_INVALID_ID,
                         pi_p4info_action_id_from_name(p4info, "bad_name"));
}

// unity uses a wrapper for the heap allocator, which does not cover strdup
char *unity_strdup(const char *s) {
  char *new_s = malloc(strlen(s) + 1);
  strcpy(new_s, s);
  return new_s;
}

#undef strdup
#define strdup unity_strdup

TEST(P4Info, ActionsStress) {
  const size_t num_actions = 4096;
  adata_t *adata = calloc(num_actions, sizeof(adata_t));

  char name[16];
  for (size_t i = 0; i < num_actions; i++) {
    adata[i].id = pi_make_action_id(i);
    snprintf(name, sizeof(name), "a%zu", i);
    adata[i].name = strdup(name);
    adata[i].num_params = i % 32;
  }

  pi_p4info_action_init(p4info, num_actions);

  for (size_t i = 0; i < num_actions; i++) {
    pi_p4info_action_add(p4info, adata[i].id, adata[i].name,
                         adata[i].num_params);
  }

  for (size_t i = 0; i < num_actions; i++) {
    for (size_t j = 0; j < adata[i].num_params; j++) {
      snprintf(name, sizeof(name), "a%zu_p%zu", i, j);
      pi_p4_id_t p_id = j;
      pi_p4info_action_add_param(p4info, adata[i].id, p_id, name, j);
    }
  }

  for (size_t i = 0; i < num_actions; i++) {
    TEST_ASSERT_EQUAL_UINT(adata[i].num_params,
                           pi_p4info_action_num_params(p4info, adata[i].id));
  }

  for (size_t i = 0; i < num_actions; i++) {
    size_t offset = 0;
    for (size_t j = 0; j < adata[i].num_params; j++) {
      snprintf(name, sizeof(name), "a%zu_p%zu", i, j);
      pi_p4_id_t p_id = j;

      TEST_ASSERT_EQUAL_UINT(
          p_id, pi_p4info_action_param_id_from_name(p4info, adata[i].id, name));

      TEST_ASSERT_EQUAL_STRING(
          name, pi_p4info_action_param_name_from_id(p4info, adata[i].id, p_id));

      TEST_ASSERT_EQUAL_UINT(
          j, pi_p4info_action_param_bitwidth(p4info, adata[i].id, p_id));

      TEST_ASSERT_EQUAL_UINT(
          offset, pi_p4info_action_param_offset(p4info, adata[i].id, p_id));
      offset += (j + 7) / 8;
    }
    TEST_ASSERT_EQUAL_UINT(offset,
                           pi_p4info_action_data_size(p4info, adata[i].id));
  }

  for (size_t i = 0; i < num_actions; i++) {
    free(adata[i].name);
  }
  free(adata);
}

TEST(P4Info, ActionsIterator) {
  const size_t num_actions = 4096;

  pi_p4info_action_init(p4info, num_actions);

  char name[16];
  for (size_t i = 0; i < num_actions; i++) {
    snprintf(name, sizeof(name), "a%zu", i);
    pi_p4info_action_add(p4info, pi_make_action_id(i), name, 0);
  }

  size_t cnt = 0;
  for (pi_p4_id_t id = pi_p4info_action_begin(p4info);
       id != pi_p4info_action_end(p4info);
       id = pi_p4info_action_next(p4info, id)) {
    snprintf(name, sizeof(name), "a%zu", cnt++);
    TEST_ASSERT_EQUAL_UINT(id, pi_p4info_action_id_from_name(p4info, name));
  }

  TEST_ASSERT_EQUAL_UINT(num_actions, cnt);
}

TEST(P4Info, TablesInvalidId) {
  const size_t num_tables = 1;
  pi_p4info_table_init(p4info, num_tables);
  TEST_ASSERT_EQUAL_UINT(PI_INVALID_ID,
                         pi_p4info_table_id_from_name(p4info, "bad_name"));
}

typedef struct {
  pi_p4_id_t id;
  char name[16];
  size_t num_match_fields;
  size_t num_actions;
  pi_p4_id_t match_fields[32];
  pi_p4_id_t actions[32];
} tdata_t;

void gen_rand_ids(pi_p4_id_t *ids, pi_p4_id_t max, size_t num) {
  Pvoid_t set = (Pvoid_t)NULL;
  for (size_t i = 0; i < num; i++) {
    int Rc = 1;
    pi_p4_id_t v;
    while (Rc) {
      v = rand() % max;
      J1T(Rc, set, v);
    }
    J1S(Rc, set, v);
    ids[i] = v;
  }
  Word_t Rc_word;
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wsign-compare"
  J1FA(Rc_word, set);
#pragma GCC diagnostic pop
}

static void check_default_action(pi_p4_id_t tid, pi_p4_id_t expected_id) {
  TEST_ASSERT_EQUAL_INT(expected_id != PI_INVALID_ID,
                        pi_p4info_table_has_const_default_action(p4info, tid));
  bool has_mutable_params;
  pi_p4_id_t default_action_id = pi_p4info_table_get_const_default_action(
      p4info, tid, &has_mutable_params);
  TEST_ASSERT_EQUAL_UINT(expected_id, default_action_id);
  // no const default action <=> params are mutable
  TEST_ASSERT_EQUAL_INT(expected_id == PI_INVALID_ID, has_mutable_params);
}

TEST(P4Info, TablesStress) {
  size_t num_actions = 1024;
  size_t num_tables = 256;
  pi_p4info_action_init(p4info, num_actions);
  pi_p4info_table_init(p4info, num_tables);

  tdata_t *tdata = calloc(num_tables, sizeof(tdata_t));

  char name[16];
  for (size_t i = 0; i < num_actions; i++) {
    snprintf(name, sizeof(name), "a%zu", i);
    // no params to make things easier
    pi_p4info_action_add(p4info, pi_make_action_id(i), name, 0);
  }

  size_t max_match_fields = sizeof(tdata[0].match_fields) / sizeof(pi_p4_id_t);
  size_t max_actions = sizeof(tdata[0].actions) / sizeof(pi_p4_id_t);

  for (size_t i = 0; i < num_tables; i++) {
    tdata[i].id = pi_make_table_id(i);
    snprintf(tdata[i].name, sizeof(tdata[i].name), "t%zu", i);
    tdata[i].num_match_fields = rand() % (max_match_fields + 1);
    tdata[i].num_actions = rand() % (max_actions + 1);
    pi_p4info_table_add(p4info, tdata[i].id, tdata[i].name,
                        tdata[i].num_match_fields, tdata[i].num_actions,
                        DEFAULT_TABLE_SIZE, DEFAULT_TABLE_IS_CONST,
                        DEFAULT_TABLE_IDLE_TIMEOUT);
    for (size_t j = 0; j < tdata[i].num_match_fields; j++) {
      pi_p4_id_t id = j;
      snprintf(name, sizeof(name), "f%zu", (size_t)id);
      tdata[i].match_fields[j] = id;
      pi_p4info_match_type_t match_type = (i + j) % PI_P4INFO_MATCH_TYPE_END;
      size_t bw =
          (match_type == PI_P4INFO_MATCH_TYPE_VALID) ? 1 : (1 + j % 128);
      // name and bw consistent with field initialization above
      pi_p4info_table_add_match_field(p4info, tdata[i].id, id, name, match_type,
                                      bw);
    }
    gen_rand_ids(tdata[i].actions, num_actions, tdata[i].num_actions);
    for (size_t j = 0; j < tdata[i].num_actions; j++) {
      tdata[i].actions[j] = pi_make_action_id(tdata[i].actions[j]);
      pi_p4_id_t id = tdata[i].actions[j];
      pi_p4info_table_add_action(p4info, tdata[i].id, id,
                                 PI_P4INFO_ACTION_SCOPE_TABLE_AND_DEFAULT);
    }
  }

  for (size_t i = 0; i < num_tables; i++) {
    TEST_ASSERT_EQUAL_UINT(tdata[i].id,
                           pi_p4info_table_id_from_name(p4info, tdata[i].name));
    TEST_ASSERT_EQUAL_STRING(tdata[i].name,
                             pi_p4info_table_name_from_id(p4info, tdata[i].id));

    TEST_ASSERT_EQUAL_UINT(
        tdata[i].num_match_fields,
        pi_p4info_table_num_match_fields(p4info, tdata[i].id));
    size_t num;
    const pi_p4_id_t *ids =
        pi_p4info_table_get_match_fields(p4info, tdata[i].id, &num);
    TEST_ASSERT_EQUAL_UINT(tdata[i].num_match_fields, num);
    if (num > 0) {
      TEST_ASSERT_EQUAL_MEMORY(tdata[i].match_fields, ids,
                               sizeof(pi_p4_id_t) * num);
    }
    for (size_t j = 0; j < tdata[i].num_match_fields; j++) {
      TEST_ASSERT_TRUE(pi_p4info_table_is_match_field_of(
          p4info, tdata[i].id, tdata[i].match_fields[j]));
    }
    TEST_ASSERT_FALSE(pi_p4info_table_is_match_field_of(
        p4info, tdata[i].id, tdata[i].num_match_fields));
    for (size_t j = 0; j < tdata[i].num_match_fields; j++) {
      TEST_ASSERT_EQUAL_UINT(
          j, pi_p4info_table_match_field_index(p4info, tdata[i].id,
                                               tdata[i].match_fields[j]));
    }
    TEST_ASSERT_EQUAL_UINT((size_t)-1,
                           pi_p4info_table_match_field_index(
                               p4info, tdata[i].id, tdata[i].num_match_fields));
    size_t offset = 0;
    for (size_t j = 0; j < tdata[i].num_match_fields; j++) {
      const pi_p4info_match_field_info_t *finfo =
          pi_p4info_table_match_field_info(p4info, tdata[i].id, j);
      TEST_ASSERT_EQUAL_UINT(tdata[i].match_fields[j], finfo->mf_id);
      TEST_ASSERT_EQUAL_STRING(
          pi_p4info_table_match_field_name_from_id(p4info, tdata[i].id,
                                                   tdata[i].match_fields[j]),
          finfo->name);
      pi_p4info_match_type_t match_type = (i + j) % PI_P4INFO_MATCH_TYPE_END;
      size_t bw =
          (match_type == PI_P4INFO_MATCH_TYPE_VALID) ? 1 : (1 + j % 128);
      TEST_ASSERT_EQUAL_INT(match_type, finfo->match_type);
      TEST_ASSERT_EQUAL_UINT(bw, finfo->bitwidth);
      TEST_ASSERT_EQUAL_UINT(offset, pi_p4info_table_match_field_offset(
                                         p4info, tdata[i].id, finfo->mf_id));
      offset += get_match_key_size_one_field(match_type, bw);
    }
    TEST_ASSERT_EQUAL_UINT(offset,
                           pi_p4info_table_match_key_size(p4info, tdata[i].id));

    TEST_ASSERT_EQUAL_UINT(tdata[i].num_actions,
                           pi_p4info_table_num_actions(p4info, tdata[i].id));
    ids = pi_p4info_table_get_actions(p4info, tdata[i].id, &num);
    TEST_ASSERT_EQUAL_UINT(tdata[i].num_actions, num);
    if (num > 0) {
      TEST_ASSERT_EQUAL_MEMORY(tdata[i].actions, ids, sizeof(pi_p4_id_t) * num);
    }
    for (size_t j = 0; j < tdata[i].num_actions; j++) {
      TEST_ASSERT_TRUE(pi_p4info_table_is_action_of(p4info, tdata[i].id,
                                                    tdata[i].actions[j]));
    }
    TEST_ASSERT_FALSE(
        pi_p4info_table_is_action_of(p4info, tdata[i].id, num_actions + 1));
  }

  for (size_t i = 0; i < num_tables; i++) {
    if (tdata[i].num_actions == 0) continue;
    pi_p4_id_t action_id = tdata[i].actions[0];
    check_default_action(tdata[i].id, PI_INVALID_ID);

    pi_p4info_table_set_const_default_action(p4info, tdata[i].id, action_id);
    check_default_action(tdata[i].id, action_id);
  }

  free(tdata);
}

TEST(P4Info, TablesIterator) {
  const size_t num_tables = 4096;

  pi_p4info_table_init(p4info, num_tables);

  char name[16];
  for (size_t i = 0; i < num_tables; i++) {
    snprintf(name, sizeof(name), "a%zu", i);
    pi_p4info_table_add(p4info, pi_make_table_id(i), name, 0, 1,
                        DEFAULT_TABLE_SIZE, DEFAULT_TABLE_IS_CONST,
                        DEFAULT_TABLE_IDLE_TIMEOUT);
  }

  size_t cnt = 0;
  for (pi_p4_id_t id = pi_p4info_table_begin(p4info);
       id != pi_p4info_table_end(p4info);
       id = pi_p4info_table_next(p4info, id)) {
    snprintf(name, sizeof(name), "a%zu", cnt++);
    TEST_ASSERT_EQUAL_UINT(id, pi_p4info_table_id_from_name(p4info, name));
  }

  TEST_ASSERT_EQUAL_UINT(num_tables, cnt);
}

TEST(P4Info, Serialize) {
  pi_p4info_t *p4info;
  char *config = read_file(TESTDATADIR
                           "/"
                           "simple_router.json");
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS,
                    pi_add_config(config, PI_CONFIG_TYPE_BMV2_JSON, &p4info));

  char *dump = pi_serialize_config(p4info, 0);
  TEST_ASSERT_NOT_NULL(dump);

  pi_p4info_t *p4info_new;
  TEST_ASSERT_EQUAL(
      PI_STATUS_SUCCESS,
      pi_add_config(dump, PI_CONFIG_TYPE_NATIVE_JSON, &p4info_new));

  char *dump_new = pi_serialize_config(p4info_new, 0);
  TEST_ASSERT_NOT_NULL(dump_new);

  TEST_ASSERT_TRUE(cmp_cJSON(dump, dump_new));

  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy_config(p4info));
  TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS, pi_destroy_config(p4info_new));
  free(dump);
  free(dump_new);
  free(config);
}

static void add_one_of_each() {
  pi_p4info_action_init(p4info, 1);
  pi_p4info_table_init(p4info, 1);
  pi_p4info_act_prof_init(p4info, 1);
  pi_p4info_counter_init(p4info, 1);
  pi_p4info_meter_init(p4info, 1);

  pi_p4info_action_add(p4info, pi_make_action_id(0), "action0", 0);
  pi_p4info_table_add(p4info, pi_make_table_id(0), "table0", 0, 0, 128,
                      DEFAULT_TABLE_IS_CONST, DEFAULT_TABLE_IDLE_TIMEOUT);
  pi_p4info_act_prof_add(p4info, pi_make_act_prof_id(0), "act_prof0", false, 8);
  pi_p4info_counter_add(p4info, pi_make_counter_id(0), "counter0",
                        PI_P4INFO_COUNTER_UNIT_BOTH, 128);
  pi_p4info_meter_add(p4info, pi_make_meter_id(0), "meter0",
                      PI_P4INFO_METER_UNIT_PACKETS,
                      PI_P4INFO_METER_TYPE_COLOR_UNAWARE, 128);
}

TEST(P4Info, Generic) {
  add_one_of_each();

  pi_res_type_id_t types[] = {PI_ACTION_ID, PI_TABLE_ID, PI_ACT_PROF_ID,
                              PI_COUNTER_ID, PI_METER_ID};
  size_t num_types = sizeof(types) / sizeof(types[0]);

  for (size_t i = 0; i < num_types; i++) {
    pi_p4_id_t id = types[i] << 24;
    const char *name = pi_p4info_any_name_from_id(p4info, id);
    TEST_ASSERT_NOT_NULL(name);
    TEST_ASSERT_EQUAL_UINT(id,
                           pi_p4info_any_id_from_name(p4info, types[i], name));

    TEST_ASSERT_EQUAL_UINT(1u, pi_p4info_any_num(p4info, types[i]));
    TEST_ASSERT_EQUAL_UINT(id, pi_p4info_any_begin(p4info, types[i]));
    TEST_ASSERT_EQUAL_UINT(pi_p4info_any_end(p4info, types[i]),
                           pi_p4info_any_next(p4info, id));

    const char *alias = "alias";
    TEST_ASSERT_EQUAL(PI_STATUS_SUCCESS,
                      pi_p4info_add_alias(p4info, id, "alias"));
    TEST_ASSERT_EQUAL_UINT(id,
                           pi_p4info_any_id_from_name(p4info, types[i], alias));
    TEST_ASSERT_EQUAL(PI_STATUS_ALIAS_ALREADY_EXISTS,
                      pi_p4info_add_alias(p4info, id, "alias"));
  }
}

TEST(P4Info, ActProfsStress) {
  const size_t num_act_profs = 100;
  const size_t num_tables = 100;

  pi_p4info_act_prof_init(p4info, num_act_profs);

  char ap_name[16];
  for (size_t i = 0; i < num_act_profs; i++) {
    pi_p4_id_t ap_id = pi_make_act_prof_id(i);
    snprintf(ap_name, sizeof(ap_name), "act_prof%zu", i);
    pi_p4info_act_prof_add(p4info, ap_id, ap_name, false, 1024);
    for (size_t j = 0; j < num_tables; j++) {
      pi_p4_id_t t_id = pi_make_table_id(j);
      pi_p4info_act_prof_add_table(p4info, ap_id, t_id);
    }
  }
}

TEST_GROUP_RUNNER(P4Info) {
  RUN_TEST_CASE(P4Info, Actions);
  RUN_TEST_CASE(P4Info, ActionsInvalidId);
  RUN_TEST_CASE(P4Info, ActionsStress);
  RUN_TEST_CASE(P4Info, ActionsIterator);
  RUN_TEST_CASE(P4Info, TablesInvalidId);
  RUN_TEST_CASE(P4Info, TablesStress);
  RUN_TEST_CASE(P4Info, TablesIterator);
  RUN_TEST_CASE(P4Info, Serialize);
  RUN_TEST_CASE(P4Info, Generic);
  RUN_TEST_CASE(P4Info, ActProfsStress);
}

void test_p4info() { RUN_TEST_GROUP(P4Info); }

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

#include "PI/p4info.h"
#include "p4info/p4info_struct.h"
#include "p4info/fields_int.h"
#include "p4info/actions_int.h"
#include "p4info/tables_int.h"
#include "read_file.h"

#include "utils.h"

#include "unity/unity_fixture.h"

#include <string.h>
#include <Judy.h>

static pi_p4info_t *p4info;

TEST_GROUP(P4Info);

TEST_SETUP(P4Info) { pi_add_config(NULL, PI_CONFIG_TYPE_NONE, &p4info); }

TEST_TEAR_DOWN(P4Info) { pi_destroy_config(p4info); }

TEST(P4Info, Fields) {
  const size_t num_fields = 3;
  const pi_p4_id_t f0 = pi_make_field_id(0), f1 = pi_make_field_id(1),
                   f2 = pi_make_field_id(2);
  const size_t bw0 = 11, bw1 = 16, bw2 = 128;
  const char *n0 = "f0", *n1 = "f1", *n2 = "f2";

  pi_p4info_field_init(p4info, num_fields);

  // adding them out of order on purpose
  pi_p4info_field_add(p4info, f1, n1, bw1);
  pi_p4info_field_add(p4info, f0, n0, bw0);
  pi_p4info_field_add(p4info, f2, n2, bw2);

  TEST_ASSERT_EQUAL_UINT(f0, pi_p4info_field_id_from_name(p4info, n0));
  TEST_ASSERT_EQUAL_UINT(f1, pi_p4info_field_id_from_name(p4info, n1));
  TEST_ASSERT_EQUAL_UINT(f2, pi_p4info_field_id_from_name(p4info, n2));

  TEST_ASSERT_EQUAL_STRING(n0, pi_p4info_field_name_from_id(p4info, f0));
  TEST_ASSERT_EQUAL_STRING(n1, pi_p4info_field_name_from_id(p4info, f1));
  TEST_ASSERT_EQUAL_STRING(n2, pi_p4info_field_name_from_id(p4info, f2));

  TEST_ASSERT_EQUAL_UINT(bw0, pi_p4info_field_bitwidth(p4info, f0));
  TEST_ASSERT_EQUAL_UINT(bw1, pi_p4info_field_bitwidth(p4info, f1));
  TEST_ASSERT_EQUAL_UINT(bw2, pi_p4info_field_bitwidth(p4info, f2));
}

TEST(P4Info, FieldsInvalidId) {
  const size_t num_fields = 1;
  pi_p4info_field_init(p4info, num_fields);
  TEST_ASSERT_EQUAL_UINT(PI_INVALID_ID,
                         pi_p4info_field_id_from_name(p4info, "bad_name"));
}

TEST(P4Info, FieldsByte0Mask) {
  const size_t num_fields = 128;

  pi_p4info_field_init(p4info, num_fields);

  for (size_t i = 0; i < num_fields; i++) {
    char name[16];
    snprintf(name, sizeof(name), "f%zu", i);
    pi_p4info_field_add(p4info, pi_make_field_id(i), name, i + 1);
  }

  TEST_ASSERT_EQUAL_HEX8(
      0x01, pi_p4info_field_byte0_mask(p4info, pi_make_field_id(0)));
  TEST_ASSERT_EQUAL_HEX8(
      0x03, pi_p4info_field_byte0_mask(p4info, pi_make_field_id(1)));
  TEST_ASSERT_EQUAL_HEX8(
      0x07, pi_p4info_field_byte0_mask(p4info, pi_make_field_id(2)));
  TEST_ASSERT_EQUAL_HEX8(
      0x0f, pi_p4info_field_byte0_mask(p4info, pi_make_field_id(3)));
  TEST_ASSERT_EQUAL_HEX8(
      0x1f, pi_p4info_field_byte0_mask(p4info, pi_make_field_id(4)));
  TEST_ASSERT_EQUAL_HEX8(
      0x3f, pi_p4info_field_byte0_mask(p4info, pi_make_field_id(5)));
  TEST_ASSERT_EQUAL_HEX8(
      0x7f, pi_p4info_field_byte0_mask(p4info, pi_make_field_id(6)));
  TEST_ASSERT_EQUAL_HEX8(
      0xff, pi_p4info_field_byte0_mask(p4info, pi_make_field_id(7)));
  for (size_t i = 8; i < num_fields; i++) {
    char mask;
    size_t bitwidth = i + 1;
    mask = (bitwidth % 8 == 0) ? 0xff : ((1 << (bitwidth % 8)) - 1);
    TEST_ASSERT_EQUAL_HEX8(
        mask, pi_p4info_field_byte0_mask(p4info, pi_make_field_id(i)));
  }
}

TEST(P4Info, FieldsStress) {
  const size_t num_fields = 4096;

  pi_p4info_field_init(p4info, num_fields);

  char name[16];
  for (size_t i = 0; i < num_fields; i++) {
    snprintf(name, sizeof(name), "f%zu", i);
    pi_p4info_field_add(p4info, pi_make_field_id(i), name, 1 + (i % 128));
  }

  for (size_t i = 0; i < num_fields; i++) {
    snprintf(name, sizeof(name), "f%zu", i);
    TEST_ASSERT_EQUAL_UINT(pi_make_field_id(i),
                           pi_p4info_field_id_from_name(p4info, name));
  }

  for (size_t i = 0; i < num_fields; i++) {
    snprintf(name, sizeof(name), "f%zu", i);
    TEST_ASSERT_EQUAL_STRING(
        name, pi_p4info_field_name_from_id(p4info, pi_make_field_id(i)));
  }

  for (size_t i = 0; i < num_fields; i++) {
    TEST_ASSERT_EQUAL_UINT(
        1 + (i % 128), pi_p4info_field_bitwidth(p4info, pi_make_field_id(i)));
  }
}

TEST(P4Info, FieldsIterator) {
  const size_t num_fields = 4096;

  pi_p4info_field_init(p4info, num_fields);

  char name[16];
  for (size_t i = 0; i < num_fields; i++) {
    snprintf(name, sizeof(name), "f%zu", i);
    pi_p4info_field_add(p4info, pi_make_field_id(i), name, 1 + (i % 128));
  }

  size_t cnt = 0;
  for (pi_p4_id_t id = pi_p4info_field_begin(p4info);
       id != pi_p4info_field_end(p4info);
       id = pi_p4info_field_next(p4info, id)) {
    snprintf(name, sizeof(name), "f%zu", cnt++);
    TEST_ASSERT_EQUAL_UINT(id, pi_p4info_field_id_from_name(p4info, name));
  }

  TEST_ASSERT_EQUAL_UINT(num_fields, cnt);
}

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

  pi_p4_id_t param_0_0 = pi_make_action_param_id(adata_0.id, 0);
  pi_p4_id_t param_0_1 = pi_make_action_param_id(adata_0.id, 1);

  // out of order on purpose
  pi_p4info_action_add_param(p4info, adata_0.id, param_0_1, param_names[1],
                             param_bws[1]);
  pi_p4info_action_add_param(p4info, adata_0.id, param_0_0, param_names[0],
                             param_bws[0]);

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

  TEST_ASSERT_EQUAL_STRING(
      param_names[0], pi_p4info_action_param_name_from_id(p4info, param_0_0));
  TEST_ASSERT_EQUAL_STRING(
      param_names[1], pi_p4info_action_param_name_from_id(p4info, param_0_1));

  TEST_ASSERT_EQUAL_UINT(param_bws[0],
                         pi_p4info_action_param_bitwidth(p4info, param_0_0));
  TEST_ASSERT_EQUAL_UINT(param_bws[1],
                         pi_p4info_action_param_bitwidth(p4info, param_0_1));

  TEST_ASSERT_EQUAL_UINT(param_offsets[0],
                         pi_p4info_action_param_offset(p4info, param_0_0));
  TEST_ASSERT_EQUAL_UINT(param_offsets[1],
                         pi_p4info_action_param_offset(p4info, param_0_1));
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
      pi_p4_id_t p_id = pi_make_action_param_id(adata[i].id, j);
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
      pi_p4_id_t p_id = pi_make_action_param_id(adata[i].id, j);

      TEST_ASSERT_EQUAL_UINT(
          p_id, pi_p4info_action_param_id_from_name(p4info, adata[i].id, name));

      TEST_ASSERT_EQUAL_STRING(
          name, pi_p4info_action_param_name_from_id(p4info, p_id));

      TEST_ASSERT_EQUAL_UINT(j, pi_p4info_action_param_bitwidth(p4info, p_id));

      TEST_ASSERT_EQUAL_UINT(offset,
                             pi_p4info_action_param_offset(p4info, p_id));
      offset += (j + 7) / 8;
    }
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

TEST(P4Info, TablesStress) {
  // tables are more complex than fields & actions, because tables reference
  // actions and fields
  size_t num_fields = 4096;
  size_t num_actions = 1024;
  size_t num_tables = 256;
  pi_p4info_field_init(p4info, num_fields);
  pi_p4info_action_init(p4info, num_actions);
  pi_p4info_table_init(p4info, num_tables);

  tdata_t *tdata = calloc(num_tables, sizeof(tdata_t));

  char name[16];
  for (size_t i = 0; i < num_fields; i++) {
    snprintf(name, sizeof(name), "f%zu", i);
    pi_p4info_field_add(p4info, pi_make_field_id(i), name, 1 + i % 128);
  }
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
                        tdata[i].num_match_fields, tdata[i].num_actions);
    gen_rand_ids(tdata[i].match_fields, num_fields, tdata[i].num_match_fields);
    for (size_t j = 0; j < tdata[i].num_match_fields; j++) {
      pi_p4_id_t id = tdata[i].match_fields[j];
      snprintf(name, sizeof(name), "f%zu", (size_t)id);
      id = pi_make_field_id(id);
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
      pi_p4info_table_add_action(p4info, tdata[i].id, id);
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
    TEST_ASSERT_FALSE(
        pi_p4info_table_is_match_field_of(p4info, tdata[i].id, num_fields + 1));
    for (size_t j = 0; j < tdata[i].num_match_fields; j++) {
      TEST_ASSERT_EQUAL_UINT(
          j, pi_p4info_table_match_field_index(p4info, tdata[i].id,
                                               tdata[i].match_fields[j]));
    }
    TEST_ASSERT_EQUAL_UINT(
        (size_t)-1,
        pi_p4info_table_match_field_index(p4info, tdata[i].id, num_fields + 1));
    size_t offset = 0;
    for (size_t j = 0; j < tdata[i].num_match_fields; j++) {
      pi_p4info_match_field_info_t finfo;
      pi_p4info_table_match_field_info(p4info, tdata[i].id, j, &finfo);
      TEST_ASSERT_EQUAL_UINT(tdata[i].match_fields[j], finfo.field_id);
      TEST_ASSERT_EQUAL_STRING(
          pi_p4info_field_name_from_id(p4info, tdata[i].match_fields[j]),
          finfo.name);
      pi_p4info_match_type_t match_type = (i + j) % PI_P4INFO_MATCH_TYPE_END;
      size_t bw =
          (match_type == PI_P4INFO_MATCH_TYPE_VALID) ? 1 : (1 + j % 128);
      TEST_ASSERT_EQUAL_INT(match_type, finfo.match_type);
      TEST_ASSERT_EQUAL_UINT(bw, finfo.bitwidth);
      TEST_ASSERT_EQUAL_UINT(offset, pi_p4info_table_match_field_offset(
                                         p4info, tdata[i].id, finfo.field_id));
      offset += get_match_key_size_one_field(match_type, bw);
    }

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
    TEST_ASSERT_FALSE(
        pi_p4info_table_has_const_default_action(p4info, tdata[i].id));
    TEST_ASSERT_EQUAL_UINT(
        PI_INVALID_ID,
        pi_p4info_table_get_const_default_action(p4info, tdata[i].id));

    pi_p4info_table_set_const_default_action(p4info, tdata[i].id, action_id);
    TEST_ASSERT_TRUE(
        pi_p4info_table_has_const_default_action(p4info, tdata[i].id));
    TEST_ASSERT_EQUAL_UINT(action_id, pi_p4info_table_get_const_default_action(
                                          p4info, tdata[i].id));
  }

  free(tdata);
}

TEST(P4Info, TablesIterator) {
  const size_t num_tables = 4096;

  pi_p4info_table_init(p4info, num_tables);

  char name[16];
  for (size_t i = 0; i < num_tables; i++) {
    snprintf(name, sizeof(name), "a%zu", i);
    pi_p4info_table_add(p4info, pi_make_table_id(i), name, 0, 1);
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

TEST_GROUP_RUNNER(P4Info) {
  RUN_TEST_CASE(P4Info, Fields);
  RUN_TEST_CASE(P4Info, FieldsInvalidId);
  RUN_TEST_CASE(P4Info, FieldsByte0Mask);
  RUN_TEST_CASE(P4Info, FieldsStress);
  RUN_TEST_CASE(P4Info, FieldsIterator);
  RUN_TEST_CASE(P4Info, Actions);
  RUN_TEST_CASE(P4Info, ActionsInvalidId);
  RUN_TEST_CASE(P4Info, ActionsStress);
  RUN_TEST_CASE(P4Info, ActionsIterator);
  RUN_TEST_CASE(P4Info, TablesInvalidId);
  RUN_TEST_CASE(P4Info, TablesStress);
  RUN_TEST_CASE(P4Info, TablesIterator);
  RUN_TEST_CASE(P4Info, Serialize);
}

void test_p4info() { RUN_TEST_GROUP(P4Info); }

/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <stdlib.h>  // needed by cJSON (for size_t)
#include <cJSON/cJSON.h>

#include <string.h>

static int cmp_cJSON_(const cJSON *json_1, const cJSON *json_2, int is_array,
                      int is_object) {
  if (json_1 == json_2) return 1;
  if ((!json_1) || (!json_2)) return 0;
  if (json_1->type != json_2->type) return 0;
  int tmp = 0;
  switch (json_1->type) {
    case cJSON_String:
      tmp = !strcmp(json_1->valuestring, json_2->valuestring);
      break;
    case cJSON_Number:
      tmp = ((json_1->valueint == json_2->valueint) &&
             (json_1->valuedouble == json_2->valuedouble));
      break;
    case cJSON_NULL:
      tmp = 1;
      break;
    case cJSON_True:
    case cJSON_False:
      tmp = (json_1->valueint == json_2->valueint);
      break;
    case cJSON_Array:
      tmp = cmp_cJSON_(json_1->child, json_2->child, 1, 0);
      break;
    case cJSON_Object:
      tmp = cmp_cJSON_(json_1->child, json_2->child, 0, 1);
      break;
    default:
      return 0;
  }
  if (!tmp) return 0;
  if (is_array) {
    return cmp_cJSON_(json_1->next, json_2->next, 1, 0);
  }
  if (is_object) {
    if (json_1->string && json_2->string &&
        strcmp(json_1->string, json_2->string))
      return 0;
    return cmp_cJSON_(json_1->next, json_2->next, 0, 1);
  }
  return 1;
}

int cmp_cJSON(const char *json_str_1, const char *json_str_2) {
  cJSON *json_1 = cJSON_Parse(json_str_1);
  cJSON *json_2 = cJSON_Parse(json_str_2);
  int res = cmp_cJSON_(json_1, json_2, 0, 1);
  cJSON_Delete(json_1);
  cJSON_Delete(json_2);
  return res;
}

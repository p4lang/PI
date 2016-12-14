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

#include <cJSON/cJSON.h>
#include <stdlib.h>  // needed by cJSON (for size_t)

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

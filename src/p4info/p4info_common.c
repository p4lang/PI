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

#include "vector.h"

#include "p4info_common.h"
#include "p4info_struct.h"

#include <cJSON/cJSON.h>

#include <string.h>

void p4info_common_push_back_annotation(p4info_common_t *common,
                                        const char *annotation) {
  const char *annotation_copy = strdup(annotation);
  vector_push_back(common->annotations, &annotation_copy);
}

char const *const *p4info_common_annotations(p4info_common_t *common,
                                             size_t *num_annotations) {
  *num_annotations = vector_size(common->annotations);
  return vector_data(common->annotations);
}

void p4info_common_serialize(cJSON *object, const p4info_common_t *common) {
  size_t num_annotations = vector_size(common->annotations);
  if (num_annotations > 0) {
    cJSON *annotationsArray = cJSON_CreateStringArray(
        vector_data(common->annotations), num_annotations);
    cJSON_AddItemToObject(object, "annotations", annotationsArray);
  }
}

static void clean_annotation(void *e) { free(*(char **)e); }

void p4info_common_init(p4info_common_t *common) {
  common->annotations =
      vector_create_wclean(sizeof(char *), 4, clean_annotation);
}

void p4info_common_destroy(p4info_common_t *common) {
  vector_destroy(common->annotations);
}

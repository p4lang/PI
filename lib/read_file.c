/* Copyright 2013-present Barefoot Networks, Inc.
 * SPDX-License-Identifier: Apache-2.0
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

#include <stdio.h>
#include <stdlib.h>

char *read_file(const char *path) {
  char *source = NULL;
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) return NULL;

  if (fseek(fp, 0L, SEEK_END) != 0) goto cleanup;

  long bufsize = ftell(fp);
  if (bufsize < 0) goto cleanup;

  source = malloc((size_t)bufsize + 1);
  if (source == NULL) goto cleanup;

  if (fseek(fp, 0L, SEEK_SET) != 0) goto cleanup_error;

  size_t new_len = fread(source, sizeof(char), (size_t)bufsize, fp);
  if (new_len != (size_t)bufsize && ferror(fp)) goto cleanup_error;
  source[new_len] = '\0';

  fclose(fp);
  return source;

cleanup_error:
  free(source);
  source = NULL;

cleanup:
  fclose(fp);
  return source;
}

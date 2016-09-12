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

// TODO: temporary placeholder

#ifndef PI_SRC_UTILS_LOGGING_H_
#define PI_SRC_UTILS_LOGGING_H_

#include <stdio.h>

extern int _logs_on;

void pi_logs_on();
void pi_logs_off();

#ifdef PI_LOG_ON
#define PI_LOG_DEBUG(...) \
  if (_logs_on) fprintf(stderr, __VA_ARGS__)
#define PI_LOG_ERROR(...) \
  if (_logs_on) fprintf(stderr, __VA_ARGS__)
#else
#define PI_LOG_DEBUG
#define PI_LOG_ERROR
#endif

#endif  // PI_SRC_UTILS_LOGGING_H_

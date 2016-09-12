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

#ifndef PI_SRC_UTILS_UTILS_H_
#define PI_SRC_UTILS_UTILS_H_

#include <arpa/inet.h>

static inline uint64_t htonll(uint64_t n) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  return n;
#else
  return (((uint64_t)htonl(n)) << 32) + htonl(n >> 32);
#endif
}

static inline uint64_t ntohll(uint64_t n) {
#if __BYTE_ORDER__ == __BIG_ENDIAN__
  return n;
#else
  return (((uint64_t)ntohl(n)) << 32) + ntohl(n >> 32);
#endif
}

#endif  // PI_SRC_UTILS_UTILS_H_

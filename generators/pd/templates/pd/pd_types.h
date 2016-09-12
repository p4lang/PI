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

#ifndef _P4_PD_TYPES_H_
#define _P4_PD_TYPES_H_

#include <stdint.h>

/* MATCH STRUCTS */

//:: for t_name, t in tables.items():
//::   t_name = get_c_name(t_name)
//::   if not t.key:
/* ${t_name} has no match fields */

//::     continue
//::   #endif
//::   match_params = gen_match_params(t.key)
typedef struct ${pd_prefix}${t_name}_match_spec {
//::   for name, width in match_params:
//::     c_name = get_c_name(name)
//::     if width > 4:
  uint8_t ${c_name}[${width}];
//::     else:
//::       type_ = get_c_type(width)
  ${type_} ${c_name};
//::     #endif
//::   #endfor
} ${pd_prefix}${t_name}_match_spec_t;

//:: #endfor


/* ACTION STRUCTS */

//:: for a_name, a in actions.items():
//::   a_name = get_c_name(a_name)
//::   if not a.runtime_data:
/* ${a_name} has no parameters */

//::     continue
//::   #endif
//::   action_params = gen_action_params(a.runtime_data)
typedef struct ${pd_prefix}${a_name}_action_spec {
//::   for name, width in action_params:
//::     c_name = get_c_name(name)
//::     if width > 4:
  uint8_t ${c_name}[${width}];
//::     else:
//::       type_ = get_c_type(width)
  ${type_} ${c_name};
//::     #endif
//::   #endfor
} ${pd_prefix}${a_name}_action_spec_t;

//:: #endfor

#endif

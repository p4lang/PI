# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Antonin Bas (antonin@barefootnetworks.com)
#
#

# -*- coding: utf-8 -*-

import os
import sys
import re

from tenjin_wrapper import render_template

_TENJIN_PREFIX = "//::"  # Use // in prefix for C syntax processing

_THIS_DIR = os.path.dirname(os.path.realpath(__file__))

_TEMPLATES_DIR = os.path.join(_THIS_DIR, "templates")


TABLES = {}
TABLES_BY_ID = {}
ACTIONS = {}
ACTIONS_BY_ID = {}
ACT_PROFS = {}
ACT_PROFS_BY_ID = {}
COUNTER_ARRAYS = {}
COUNTER_ARRAYS_BY_ID = {}
METER_ARRAYS = {}
METER_ARRAYS_BY_ID = {}


def enum(type_name, *sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    # enums['reverse_mapping'] = reverse

    @staticmethod
    def to_str(x):
        return reverse[x].lower()
    enums['to_str'] = to_str

    @staticmethod
    def from_str(x):
        return enums[x.upper()]

    enums['from_str'] = from_str
    return type(type_name, (), enums)

MatchType = enum('MatchType', 'EXACT', 'LPM', 'TERNARY', 'VALID', 'RANGE')
TableType = enum('TableType', 'SIMPLE', 'INDIRECT', 'INDIRECT_WS')
MeterUnit = enum('MeterUnit', 'PACKETS', 'BYTES')
MeterType = enum('MeterType', 'COLOR_AWARE', 'COLOR_UNAWARE')


class Table:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.match_type = None
        self.type_ = None
        self.act_prof = None  # for indirect tables only
        self.actions = {}
        self.key = []
        self.default_action = None
        self.with_counters = False
        self.direct_meters = None
        self.support_timeout = False

        TABLES[name] = self
        TABLES_BY_ID[id_] = self

    def set_match_type(self):
        assert(self.match_type is None)
        match_types = [t[2] for t in self.key]

        if len(match_types) == 0:
            self.match_type = MatchType.EXACT
        elif "range" in match_types:
            self.match_type = MatchType.RANGE
        elif "ternary" in match_types:
            self.match_type = MatchType.TERNARY
        elif match_types.count("lpm") >= 2:
            print "cannot have 2 different lpm matches in a single table"
            sys.exit(1)
        elif "lpm" in match_types:
            self.match_type = MatchType.LPM
        else:
            # that includes the case when we only have one valid match and
            # nothing else
            self.match_type == MatchType.EXACT

    def num_key_fields(self):
        return len(self.key)

    def key_str(self):
        def one_str(f):
            name, _, t, bw = f
            return name + "(" + MatchType.to_str(t) + ", " + str(bw) + ")"

        return ",\t".join([one_str(f) for f in self.key])

    def table_str(self):
        return "{0:30} [{1}]".format(self.name, self.key_str())


class Action:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.runtime_data = []

        ACTIONS[name] = self
        ACTIONS_BY_ID[id_] = self

    def num_params(self):
        return len(self.runtime_data)

    def runtime_data_str(self):
        return ",\t".join([name + "(" + str(bw) + ")"
                           for name, bw in self.runtime_data])

    def action_str(self):
        return "{0:30} [{1}]".format(self.name, self.runtime_data_str())


class ActProf:
    def __init__(self, name, id_, with_selector):
        self.name = name
        self.id_ = id_
        self.with_selector = with_selector
        self.actions = {}

        ACT_PROFS[name] = self
        ACT_PROFS_BY_ID[id_] = self


class CounterArray:
    def __init__(self, name, id_, is_direct):
        self.name = name
        self.id_ = id_
        self.is_direct = is_direct

        COUNTER_ARRAYS[name] = self
        COUNTER_ARRAYS_BY_ID[id_] = self

    def counter_str(self):
        return "{0:30} [{1}]".format(self.name, self.is_direct)


class MeterArray:
    # hacks to make them more easily accessible in template
    MeterUnit = MeterUnit
    MeterType = MeterType

    def __init__(self, name, id_, is_direct, unit, type_):
        self.name = name
        self.id_ = id_
        self.is_direct = is_direct
        self.unit = unit
        self.type_ = type_

        METER_ARRAYS[name] = self
        METER_ARRAYS_BY_ID[id_] = self

    def meter_str(self):
        return "{0:30} [{1}, {2}]".format(self.name, self.is_direct,
                                          MeterUnit.to_str(self.unit))


def load_json(json_str):
    def get_header_type(header_name, j_headers):
        for h in j_headers:
            if h["name"] == header_name:
                return h["header_type"]
        assert(0)

    def get_field_bitwidth(header_type, field_name, j_header_types):
        for h in j_header_types:
            if h["name"] != header_type:
                continue
            for t in h["fields"]:
                # t can have a third element (field signedness)
                f, bw = t[0], t[1]
                if f == field_name:
                    return bw
        assert(0)

    # json_ = json.loads(json_str)
    json_ = json_str

    for j_action in json_["actions"]:
        action = Action(j_action["name"], j_action["id"])
        for j_param in j_action["params"]:
            pid = j_param["id"]
            action.runtime_data += [(j_param["name"], pid, j_param["bitwidth"])]

    def get_match_type(mt):
        return {0 : MatchType.VALID,
                1 : MatchType.EXACT,
                2 : MatchType.LPM,
                3 : MatchType.TERNARY,
                4 : MatchType.RANGE}[mt]

    for j_table in json_["tables"]:
        table = Table(j_table["name"], j_table["id"])
        table.type_ = TableType.SIMPLE
        for action in j_table["actions"]:
            a = ACTIONS_BY_ID[action["id"]]
            table.actions[a.name] = a
        for j_key in j_table["match_fields"]:
            fid = j_key["id"]
            match_type = get_match_type(j_key["match_type"])
            # TODO(antonin): fix this when valid match handling is improved
            field_name = j_key["name"].replace("$valid$", "valid")
            bitwidth = j_key["bitwidth"]
            table.key += [(field_name, fid, match_type, bitwidth)]
        table.set_match_type()

    if "act_profs" in json_:
        for j_act_prof in json_["act_profs"]:
            t_ids = j_act_prof["tables"]
            if not t_ids:  # should not happen
                continue
            act_prof = ActProf(j_act_prof["name"],
                               j_act_prof["id"],
                               j_act_prof["with_selector"])
            one_t = TABLES_BY_ID[t_ids[0]]
            act_prof.actions = one_t.actions

            # update type of tables
            for t_id in t_ids:
                t = TABLES_BY_ID[t_id]
                assert(t.type_ == TableType.SIMPLE)
                if act_prof.with_selector:
                    t.type_ = TableType.INDIRECT_WS
                else:
                    t.type_ = TableType.INDIRECT

    if "counters" in json_:
        for j_counter in json_["counters"]:
            # 0 is PI_INVALID_ID
            is_direct = (j_counter["direct_table"] != 0)
            counter = CounterArray(j_counter["name"], j_counter["id"],
                                   is_direct)

    if "meters" in json_:
        for j_meter in json_["meters"]:
            # 0 is PI_INVALID_ID
            direct_t_id = j_meter["direct_table"]
            is_direct = (direct_t_id != 0)
            unit = {
                1 : MeterUnit.PACKETS,
                2 : MeterUnit.BYTES,
            }[j_meter["meter_unit"]]
            type_ = {
                1 : MeterType.COLOR_AWARE,
                2 : MeterType.COLOR_UNAWARE,
            }[j_meter["meter_type"]]
            meter = MeterArray(j_meter["name"], j_meter["id"], is_direct, unit,
                               type_)
            if is_direct:
                t = TABLES_BY_ID[direct_t_id]
                t.direct_meters = meter


def ignore_template_file(filename):
    """
    Ignore these files in template dir
    """
    pattern = re.compile('^\..*|.*\.cache$|.*~$')
    return pattern.match(filename)


def gen_file_lists(current_dir, gen_dir):
    """
    Generate target files from template; only call once
    """
    files_out = []
    for root, subdirs, files in os.walk(current_dir):
        for filename in files:
            if ignore_template_file(filename):
                continue
            relpath = os.path.relpath(os.path.join(root, filename), current_dir)
            template_file = relpath
            target_file = os.path.join(gen_dir, relpath)
            files_out.append((template_file, target_file))
    return files_out


def render_all_files(render_dict, gen_dir, templates_dir):
    files = gen_file_lists(templates_dir, gen_dir)
    for template, target in files:
        path = os.path.dirname(target)
        if not os.path.exists(path):
            os.makedirs(path)
        with open(target, "w") as f:
            render_template(f, template, render_dict, templates_dir,
                            prefix=_TENJIN_PREFIX)


def _validate_dir(dir_name):
    if not os.path.isdir(dir_name):
        print dir_name, "is not a valid directory"
        sys.exit(1)
    return os.path.abspath(dir_name)


def get_c_type(byte_width):
    if byte_width == 1:
        return "uint8_t"
    elif byte_width == 2:
        return "uint16_t"
    elif byte_width <= 4:
        return "uint32_t"
    else:
        return "uint8_t *"


# key is a Python list of tuples (field_name, match_type, bitwidth)
def gen_match_params(key):
    params = []
    for field, _, match_type, bitwidth in key:
        bytes_needed = bits_to_bytes(bitwidth)
        if match_type == MatchType.RANGE:
            params += [(field + "_start", bytes_needed)]
            params += [(field + "_end", bytes_needed)]
        else:
            params += [(field, bytes_needed)]
        if match_type == MatchType.LPM:
            params += [(field + "_prefix_length", 2)]
        if match_type == MatchType.TERNARY:
            params += [(field + "_mask", bytes_needed)]
    return params


def gen_action_params(runtime_data):
    params = []
    for name, pid, bitwidth in runtime_data:
        # for some reason, I was prefixing everything with "action_" originally
        name = "action_" + name
        params += [(name, pid, bits_to_bytes(bitwidth))]
    return params


def bits_to_bytes(bw):
    return (bw + 7) / 8


def get_c_name(name):
    # TODO: improve
    n = name.replace(".", "_")
    n = n.replace("[", "_")
    n = n.replace("]", "_")
    return n


def get_thrift_type(byte_width):
    if byte_width == 1:
        return "byte"
    elif byte_width == 2:
        return "i16"
    elif byte_width <= 4:
        return "i32"
    elif byte_width == 6:
        return "MacAddr_t"
    elif byte_width == 16:
        return "IPv6_t"
    else:
        return "binary"


def generate_pd_source(json_dict, dest_dir, p4_prefix, templates_dir, target):
    TABLES.clear()
    TABLES_BY_ID.clear()
    ACTIONS.clear()
    ACTIONS_BY_ID.clear()
    ACT_PROFS.clear()
    ACT_PROFS_BY_ID.clear()
    COUNTER_ARRAYS.clear()
    COUNTER_ARRAYS_BY_ID.clear()
    METER_ARRAYS.clear()
    METER_ARRAYS_BY_ID.clear()

    load_json(json_dict)
    render_dict = {}
    render_dict["p4_prefix"] = p4_prefix
    render_dict["pd_prefix"] = "p4_pd_" + p4_prefix + "_"
    render_dict["MatchType"] = MatchType
    render_dict["TableType"] = TableType
    render_dict["MeterUnit"] = MeterUnit
    render_dict["MeterType"] = MeterType
    render_dict["gen_match_params"] = gen_match_params
    render_dict["gen_action_params"] = gen_action_params
    render_dict["bits_to_bytes"] = bits_to_bytes
    render_dict["get_c_type"] = get_c_type
    render_dict["get_c_name"] = get_c_name
    render_dict["get_thrift_type"] = get_thrift_type
    render_dict["tables"] = TABLES
    render_dict["actions"] = ACTIONS
    render_dict["act_profs"] = ACT_PROFS
    render_dict["counter_arrays"] = COUNTER_ARRAYS
    render_dict["meter_arrays"] = METER_ARRAYS
    render_dict["render_dict"] = render_dict

    if target == "bm":
        render_dict["target_common_h"] = "<bm/pdfixed/pd_common.h>"
    elif target == "tofino":
        render_dict["target_common_h"] = "<tofino/pdfixed/pd_common.h>"
    else:
        assert(0)

    render_all_files(render_dict, _validate_dir(dest_dir), templates_dir)


import argparse
import json

parser = argparse.ArgumentParser(description='PI PD-frontend generation')
parser.add_argument('source', metavar='source', type=str,
                    help='JSON source.')
parser.add_argument('--pd', dest='pd', type=str,
                    help='Generate PD C code for this P4 program'
                    ' in this directory. Directory must exist.',
                    required=True)
parser.add_argument('--p4-prefix', type=str,
                    help='P4 name use for API function prefix',
                    default="prog", required=False)
# This is temporary, need to make things uniform
parser.add_argument('--target', type=str, choices=["bm", "tofino"],
                    help='Target for which the PD frontend is generated',
                    default="bm", required=False)

def _validate_dir(path):
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        print path, "is not a valid directory"
        sys.exit(1)
    return path

def main(templates_dir=_TEMPLATES_DIR):
    args = parser.parse_args()

    path_pd = _validate_dir(args.pd)

    print "Generating PD source files in", path_pd

    with open(args.source, 'r') as f:
        json_dict = json.load(f)
        generate_pd_source(json_dict, path_pd, args.p4_prefix, templates_dir,
                           args.target)


if __name__ == "__main__":  # pragma: no cover
    main()

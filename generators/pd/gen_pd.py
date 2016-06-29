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
FIELDS = {}
FIELDS_BY_ID = {}


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
MeterType = enum('MeterType', 'PACKETS', 'BYTES')


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

    def num_key_fields(self):
        return len(self.key)

    def key_str(self):
        def one_str(f):
            name, t, bw = f
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


class Field:
    def __init__(self, name, id_, bitwidth):
        self.name = name
        self.id_ = id_
        self.bitwidth = bitwidth

        FIELDS[name] = self
        FIELDS_BY_ID[id_] = self


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

    for j_field in json_["fields"]:
        field_name = j_field["name"]
        # a bit flaky, but that's how it is in the PD
        field_name = field_name.replace("_valid", "valid")  # hack
        f = Field(field_name, j_field["id"], j_field["bitwidth"])

    for j_action in json_["actions"]:
        action = Action(j_action["name"], j_action["id"])
        for j_param in j_action["params"]:
            action.runtime_data += [(j_param["name"], j_param["bitwidth"])]

    def get_match_type(mt):
        return {0 : MatchType.VALID,
                1 : MatchType.EXACT,
                2 : MatchType.LPM,
                3 : MatchType.TERNARY,
                4 : MatchType.RANGE}[mt]

    for j_table in json_["tables"]:
        table = Table(j_table["name"], j_table["id"])
        # table.match_type = MatchType.from_str(j_table["match_type"])
        table.type_ = TableType.from_str("simple")
        for action in j_table["actions"]:
            a = ACTIONS_BY_ID[action]
            table.actions[a.name] = a
        for j_key in j_table["match_fields"]:
            fid = j_key["id"]
            match_type = get_match_type(j_key["match_type"])
            field_name, bitwidth = (FIELDS_BY_ID[fid].name,
                                    FIELDS_BY_ID[fid].bitwidth)
            table.key += [(field_name, match_type, bitwidth)]


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
    for field, match_type, bitwidth in key:
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
    for name, bitwidth in runtime_data:
        # for some reason, I was prefixing everything with "action_" originally
        name = "action_" + name
        params += [(name, bits_to_bytes(bitwidth))]
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


def generate_pd_source(json_dict, dest_dir, p4_prefix, templates_dir):
    TABLES.clear()
    TABLES_BY_ID.clear()
    ACTIONS.clear()
    ACTIONS_BY_ID.clear()
    FIELDS.clear()
    FIELDS_BY_ID.clear()

    load_json(json_dict)
    render_dict = {}
    render_dict["p4_prefix"] = p4_prefix
    render_dict["pd_prefix"] = "p4_pd_" + p4_prefix + "_"
    render_dict["MatchType"] = MatchType
    render_dict["TableType"] = TableType
    render_dict["MeterType"] = MeterType
    render_dict["gen_match_params"] = gen_match_params
    render_dict["gen_action_params"] = gen_action_params
    render_dict["bits_to_bytes"] = bits_to_bytes
    render_dict["get_c_type"] = get_c_type
    render_dict["get_c_name"] = get_c_name
    render_dict["get_thrift_type"] = get_thrift_type
    render_dict["tables"] = TABLES
    render_dict["actions"] = ACTIONS
    render_dict["fields"] = FIELDS
    render_dict["render_dict"] = render_dict
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
        generate_pd_source(json_dict, path_pd, args.p4_prefix, templates_dir)


if __name__ == "__main__":  # pragma: no cover
    main()

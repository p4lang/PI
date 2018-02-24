#! /usr/bin/python
#
# xform_anno.py - Utility to transform p4info annotations into first-class Message elements
#

# Copyright 2018-present Keysight Technologies, Inc.
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
# Chris Sommers (chris.sommers@keysight.com)
#

import p4.config.p4info_pb2 as p4info_pb2
import argparse
import sys
import google.protobuf.json_format as json_format
import google.protobuf.text_format as text_format
import textwrap

# Conditionally print a verbose message
def log_verbose(msg):
    if verbose:
        print >> sys.stderr, msg

# Set document.brief
def set_doc_brief(doc, value):
    doc.brief = value;

# Set document.description
def set_doc_description(doc, value):
    doc.description = value;

# Extract the string value embedded in an annotation
# Asssumes just one string, surrounded by escaped quotes e.g. "\"string\""
def get_anno_value(anno):
    return anno.split('(\"')[1].split('\")')[0]

# Detect @brief() and @description() annotations and transform into document.brief, document.description
def xform_doc_annotation(container_name, doc, anno_list, anno):
    if '@brief' in anno:
        log_verbose( "*** %sTransform doc anno in %s: %s => doc.brief" % (drystr, container_name, anno))
        if dry == False:
            set_doc_brief(doc, get_anno_value(anno))
            anno_list.remove(anno)

    if '@description' in anno:
        log_verbose( "*** %sTransform doc anno in %s: %s => doc.description" % (drystr, container_name, anno))
        if dry == False:
            set_doc_description(doc, get_anno_value(anno))
            anno_list.remove(anno)

# Transform annotations into preamble.document.brief, .description
def xform_preamble_doc_annotations(message):
    #reverse iterate so deleting elements doesn't cause subsequent one to get skipped
    for anno in reversed(message.preamble.annotations):
        xform_doc_annotation(message.preamble.name, message.preamble.doc, message.preamble.annotations, anno)

# Transform match_field annotations (doc)
def xform_table_match_field_annotations(table):
    for matchfield in table.match_fields:
        #reverse iterate so deleting elements doesn't cause subsequent one to get skipped
        for anno in reversed(matchfield.annotations):
            xform_doc_annotation("match_field %s.%s" %(table.preamble.name, matchfield.name),
                                 matchfield.doc, matchfield.annotations, anno)

# Transform action anotations (doc)
def xform_action_param_annotations(action):
    for param in action.params:
        #reverse iterate so deleting elements doesn't cause subsequent one to get skipped
        for anno in reversed(param.annotations):
            xform_doc_annotation("action %s(%s)" % (action.preamble.name,param.name),
                                 param.doc, param.annotations,  anno)

# Convenience function to define argument parser
def get_arg_parser():

    parser = argparse.ArgumentParser(description='P4info transform utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            Either or both of infile, outfile can be omitted; a hyphen signifies stdin and stdout, respectively.
            Using -i none or -o none overrides input/output file descriptors.

            Examples:
            =========
            xform_anno.py [opts] <infile> <outfile>        read infile, write to outfile
            xform_anno.py [opts] <infile> -                read infile, write to stdout
            xform_anno.py [opts] <infile>                  read infile, write to stdout
            xform_anno.py [opts] - <outfile>               read stdin, write to outfile
            xform_anno.py [opts] - -                       read stdin, write to stdout
            xform_anno.py [opts]                           read stdin, write to stdout

            Populate PkgInfo fields, some from cmd-line and one from a file; you can populate all pkg_xxx fields either way:

            .xform_anno.py --pkg_name "MyPackage" --pkg_brief "A cool package" --pkg_descrip "`cat descrip.txt`" <infile> <outfile>
        '''))

    # Parsing options
    parser.add_argument('-d', help='Dry-run only; report transforms (via -v) but do not make changes',
                        action="store_true", dest='dry', default=False)

    parser.add_argument('-v', help='Verbose reporting of transform steps',
                        action="store_true", dest='verbose', default=False)

    parser.add_argument('infile', nargs='?', help='Input file name (use - or omit for stdin; -i none means no input)',
                        type=argparse.FileType('rb'), default=sys.stdin)

    parser.add_argument('outfile', nargs='?',  help='Input file name  (use - or omit for stdout; -o none means no output)',
                        type=argparse.FileType('wb'), default=sys.stdout)

    parser.add_argument('-o', help='Output Format', dest='outfmt',
                        type=str, action='store', choices=['proto', 'json', 'text', 'none'],
                        default='proto')

    parser.add_argument('-i', help='Input Format', dest='infmt',
                        type=str, action='store', choices=['proto', 'json', 'none'],
                        default='proto')

    # PkgInfo elements
    parser.add_argument('--pkg_name', help='Package name', type=str, action='store')
    parser.add_argument('--pkg_doc_brief', help='Package document brief', type=str, action='store')
    parser.add_argument('--pkg_doc_descr', help='Package document description', type=str, action='store')
    parser.add_argument('--pkg_version', help='Package version', type=str, action='store')
    parser.add_argument('--pkg_arch', help='Package target architecture', type=str, action='store')
    parser.add_argument('--pkg_organization', help='Package organization', type=str, action='store')
    parser.add_argument('--pkg_contact', help='Package contact', type=str, action='store')
    parser.add_argument('--pkg_url', help='Package url', type=str, action='store')
    parser.add_argument('--pkg_anno', help='Package annotation, can use multiple times', type=str, action='append')

    return parser

# Extract cmd-line args and insert into PkgInfo Message
def add_arg_elements(args, p4info):
    if args == None:
        return
    if p4info == None:
        return

    if args.pkg_name != None:
        if dry == False:
            p4info.pkg_info.name = args.pkg_name
        log_verbose('+++ %sAdded pkg_name "%s"' % (drystr, args.pkg_name))

    if args.pkg_version != None:
        if dry == False:
            p4info.pkg_info.version = args.pkg_version
        log_verbose('+++ %sAdded pkg_version "%s"' % (drystr, args.pkg_version))

    if args.pkg_doc_brief != None:
        if dry == False:
            p4info.pkg_info.doc.brief = args.pkg_doc_brief
        log_verbose('+++ %sAdded pkg_doc_brief "%s"' % (drystr, args.pkg_doc_brief))

    if args.pkg_doc_descr != None:
        if dry == False:
            p4info.pkg_info.doc.description = args.pkg_doc_descr
        log_verbose('+++ %sAdded pkg_doc_descr "%s"' % (drystr, args.pkg_doc_descr))

    if args.pkg_arch != None:
        if dry == False:
            p4info.pkg_info.arch = args.pkg_arch
        log_verbose('+++ %sAdded pkg_arch "%s"' % (drystr, args.pkg_arch))

    if args.pkg_organization != None:
        if dry == False:
            p4info.pkg_info.organization = args.pkg_organization
        log_verbose('+++ %sAdded pkg_organization "%s"' % (drystr, args.pkg_organization))

    if args.pkg_contact != None:
        if dry == False:
            p4info.pkg_info.contact = args.pkg_contact
        log_verbose('+++ %sAdded pkg_contact "%s"' % (drystr, args.pkg_contact))

    if args.pkg_url != None:
        if dry == False:
            p4info.pkg_info.url = args.pkg_url
        log_verbose('+++ %sAdded pkg_url "%s"' % (drystr, args.pkg_url))

    if args.pkg_anno != None:
        tmp = [];
        for anno in args.pkg_anno:
            if dry == False:
                p4info.pkg_info.annotations.append(anno)
            else :
                tmp.append(anno);
        if dry == False:
            log_verbose('+++ Added pkg_anno "%s"' % (p4info.pkg_info.annotations))
        else:
            log_verbose('+++ %sAdded pkg_anno "%s"' % (drystr, tmp))


    return

########################################################
# Main - read file, transform it, write it
########################################################

#
# Get args
#
parser = get_arg_parser()
args = parser.parse_args()
verbose = args.verbose
dry = args.dry
if dry == True:
    drystr='(dry): '
else:
    drystr=''

infmt = args.infmt
outfmt = args.outfmt
if infmt != 'none':
    infile = args.infile
if outfmt != 'none':
    outfile = args.outfile

#
# Read intput into protobuf
#
p4info = p4info_pb2.P4Info()

if (infmt == 'json'):
    p4info = json_format.Parse(infile.read(), p4info_pb2.P4Info(), ignore_unknown_fields=False)
    infile.close()
elif infmt == 'proto':
    p4info.ParseFromString(infile.read())
    infile.close()

add_arg_elements(args, p4info)
#
# Transform protobuf object(s)
for table in p4info.tables:
    log_verbose("=== process table %s" % table.preamble.name)
    xform_preamble_doc_annotations(table)
    xform_table_match_field_annotations(table)

for action in p4info.actions:
    log_verbose("=== process action %s" % action.preamble.name)
    xform_preamble_doc_annotations(action)
    xform_action_param_annotations(action)

for action_profile in p4info.action_profiles:
    log_verbose("=== process action_profile %s" % action_profile.preamble.name)
    xform_preamble_doc_annotations(action_profile)

for counter in p4info.counters:
    log_verbose("=== process indirect counter %s" % counter.preamble.name)
    xform_preamble_doc_annotations(counter)

for counter in p4info.direct_counters:
    log_verbose("=== process direct_counter %s" % counter.preamble.name)
    xform_preamble_doc_annotations(counter)

for meter in p4info.meters:
    log_verbose("=== process indirect meter %s" % meter.preamble.name)
    xform_preamble_doc_annotations(meter)

for meter in p4info.direct_meters:
    log_verbose("=== process direct_meter %s" % meter.preamble.name)
    xform_preamble_doc_annotations(meter)

for extern in p4info.externs:
    for extern_instance in extern.instances:
        log_verbose("=== process extern_instance %s" % extern_instance.preamble.name)
        xform_preamble_doc_annotations(extern_instance)

#
# Write to output
#
if outfmt == 'json':
    outfile.write(json_format.MessageToJson(p4info))
    outfile.close()
elif outfmt == 'proto':
    outfile.write(p4info.SerializeToString())
    outfile.close()
elif outfmt == 'text':
    outfile.write(text_format.MessageToString(p4info))
    outfile.close()

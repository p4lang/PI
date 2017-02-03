#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Modified from https://github.com/cloderic/clang_format_check

import argparse
import glob
import os
import subprocess
import xml.etree.ElementTree as ET
import sys
import re

from collections import namedtuple
Replacement = namedtuple("Replacement", "offset length text")
Error = namedtuple("Error", "line column found expected")

# checks if the file needs to be processed or is excluded by a custom config
# adapted from cpplint.py, see license information in cpplint.py
def process_overrides(filename):
  abs_filename = os.path.abspath(filename)
  keep_looking = True
  while keep_looking:
    abs_path, base_name = os.path.split(abs_filename)
    if not base_name:
      break  # Reached the root directory.

    cfg_file = os.path.join(abs_path, ".clang_format_extra.cfg")
    abs_filename = abs_path
    if not os.path.isfile(cfg_file):
      continue

    try:
      with open(cfg_file) as file_handle:
        for line in file_handle:
          line, _, _ = line.partition('#')  # Remove comments.
          if not line.strip():
            continue

          name, _, val = line.partition('=')
          name = name.strip()
          val = val.strip()
          if name == 'set noparent':
            keep_looking = False
          elif name == 'exclude_files':
            # When matching exclude_files pattern, use the base_name of the
            # current file name or the directory name we are processing.  For
            # example, if we are checking for lint errors in /foo/bar/baz.cc and
            # we found the .cfg file at /foo/.clang_format_extra.cfg, then the
            # config file's "exclude_files" filter is meant to be checked
            # against "bar" and not "baz" nor "bar/baz.cc".
            if base_name:
              pattern = re.compile(val)
              if pattern.match(base_name):
                sys.stderr.write('Ignoring "%s": file excluded by "%s". '
                                 'File path component "%s" matches '
                                 'pattern "%s"\n' %
                                 (filename, cfg_file, base_name, val))
                return False
          else:
            sys.stderr.write(
                'Invalid configuration option (%s) in file %s\n' %
                (name, cfg_file))

    except IOError:
      sys.stderr.write(
          "Skipping config file '%s': Can't open for reading\n" % cfg_file)
      keep_looking = False

  return True

def replacements_from_file(clang_exec, file, style="file", inplace=False):
    replacements = []

    clang_format_base = [clang_exec]
    clang_format_base.append("-style={}".format(style))

    clang_format_args = clang_format_base + []  # make copy
    clang_format_args.append("-output-replacements-xml")
    clang_format_args.append(os.path.basename(file))
    replacement_xml = subprocess.check_output(clang_format_args,
                                              cwd=os.path.dirname(file))

    replacement_xml_root = ET.XML(replacement_xml)
    for replacement_item in replacement_xml_root.findall('replacement'):
        replacements.append(Replacement(
            offset=int(replacement_item.attrib["offset"]),
            length=int(replacement_item.attrib["length"]),
            text=replacement_item.text
        ))

    # inplace editing if required
    # apparently, "-output-replacements-xml" and "-i" cannot be combined
    if replacements and inplace:
        print "Editing", file, "to fix errors"
        clang_format_args = clang_format_base + []
        clang_format_args.append("-i")
        clang_format_args.append(os.path.basename(file))
        subprocess.check_output(clang_format_args, cwd=os.path.dirname(file))

    return replacements


def errors_from_replacements(file, replacements=[]):
    errors = []

    lines = [0]  # line index to character offset
    file_content = ""
    for line in open(file, "r"):
        file_content += line
        lines.append(lines[-1] + len(line))

    for line_index, line_offset in enumerate(lines[:-1]):
        while (len(replacements) > 0 and
               lines[line_index + 1] > replacements[0].offset):
            replacement = replacements.pop(0)
            errors.append(Error(
                line=line_index,
                column=replacement.offset - line_offset,
                found=file_content[replacement.offset:replacement.offset +
                                   replacement.length],
                expected=replacement.text if replacement.text else ""
            ))

        if len(replacements) == 0:
            break

    return errors


def clang_format_check(clang_exec, files=[], style="file", inplace=False):
    error_count = 0
    file_errors = dict()

    for file in files:
        if not process_overrides(file):
            print "Skipping", file
            continue
        replacements = replacements_from_file(clang_exec, file, style,
                                              inplace=inplace)
        errors = errors_from_replacements(file, replacements)
        error_count += len(errors)
        file_errors[file] = errors
    return error_count, file_errors


def print_error_report(error_count, file_errors):
    if error_count == 0:
        print "No format error found"
    else:
        for file, errors in file_errors.iteritems():
            print "-- {} format errors at {}:".format(len(errors), file)
            for error in errors:
                print "    ({},{})".format(error.line + 1, error.column + 1)
                # print "        - found: \"{}\"".format(error.found)
                # print "        - expected: \"{}\"".format(error.expected)
        print "---"
        print "A total of {} format errors were found".format(error_count)


def check_clang_format_exec(clang_exec):
    try:
        subprocess.check_output([clang_exec, "-version"])
        return True
    except subprocess.CalledProcessError, e:
        # it seems that in some version of clang-format '-version' leads to
        # non-zero exist status
        return True
    except OSError, e:
        return False

def main():
    parser = argparse.ArgumentParser(
        description="C/C++ formatting check using clang-format")

    # Style
    parser.add_argument("-s", "--style",
                        default="file",
                        help="Coding style, pass-through to clang-format's "
                        "-style=<string>, (default is '%(default)s').")

    # Exit cleanly on missing clang-format
    parser.add_argument("-e", "--exe",
                        required=False,
                        help="The clang-format executable to use, by default "
                        "we will try 'clang-format', 'clang-format-3.8' and "
                        "'clang-format-3.6'")

    # Files or directory to check
    parser.add_argument("file", nargs="+", help="Paths to the files that'll "
                        "be checked (wilcards accepted).")

    # Inplace edit
    parser.add_argument("-i", action="store_true", default=False,
                        help="Inplace edit <file>s, if specified.")

    args = parser.parse_args()

    # Adding the double quotes around the inline style
    if len(args.style) > 0 and args.style[0] == "{":
        args.style = "\"" + args.style + "\""

    # Checking that clang-format is available
    clang_exec = None
    if args.exe:
        if not check_clang_format_exec(args.exe):
            print "Can't run provided binary '{}'".format(args.exe)
            exit(-1)
        clang_exec = args.exe
    else:
        for e in ["clang-format", "clang-format-3.8", "clang-format-3.6"]:
            if check_clang_format_exec(e):
                clang_exec = e
                break
        if clang_exec is None:
            print "Can't run 'clang-format', please make sure it is installed "
            "and reachable in your PATH."
            exit(-1)

    print "Using", clang_exec

    # globing the file paths
    files = set()
    for pattern in args.file:
        for file in glob.iglob(pattern):
            files.add(os.path.relpath(file))

    file_list = list(files)
    print "Checking {} files...".format(len(file_list))
    error_count, file_errors = clang_format_check(clang_exec,
                                                  style=args.style,
                                                  files=file_list,
                                                  inplace=args.i)
    print_error_report(error_count, file_errors)
    exit(error_count)

if __name__ == "__main__":
    main()

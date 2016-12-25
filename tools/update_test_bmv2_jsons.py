#!/usr/bin/env python2

import argparse
import fnmatch
import os
import subprocess
import sys

def find_files(root):
    files = []
    for path_prefix, _, filenames in os.walk(root, followlinks=False):
        for filename in fnmatch.filter(filenames, '*.p4'):
            path = os.path.join(path_prefix, filename)
            json_path = os.path.splitext(path)[0] + ".json"
            if os.path.exists(json_path):
                files.append([path, json_path])
    return files

def check_compiler_exec(path):
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.check_call([path, "--version"],
                                  stdout=devnull, stderr=devnull)
        return True
    except subprocess.CalledProcessError:
        return True
    except OSError:  # exec not found
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Search for P4 files recursively in provided directory "
        "and if they have a JSON equivalent regenerates it using the bmv2 "
        "compiler.")
    parser.add_argument("--root", type=str, default=os.getcwd(),
                        help="Directory in which to recursively search for P4 "
                        "files. Default is current working directory.")
    parser.add_argument("--compiler", type=str, default="p4c-bmv2",
                        help="bmv2 compiler to use. Default is p4c-bmv2.")
    args = parser.parse_args()

    if not check_compiler_exec(args.compiler):
        print "Cannot use provided compiler"
        sys.exit(1)

    files = find_files(args.root)
    for input_f, output_f in files:
        print "Regenerating", input_f, "->", output_f
        try:
            cmd = [args.compiler, input_f, "--json", output_f, "--keep-pragmas"]
            with open(os.devnull, 'w') as devnull:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            print "ERROR"
            print " ".join(cmd)
            print out
        except OSError:
            print "FATAL ERROR"
            sys.exit(2)

if __name__ == '__main__':
    main()

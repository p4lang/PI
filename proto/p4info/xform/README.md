# P4Info xform - transformation utilities
This directory contains utilities and examples for manipulating P4Info protobuf files to enhance the data models with new message elements, to facilitiate control plane API and UI generation, P4 package management, etc. The long-term goal is to establish some new conventions in P4 source code which will result in additional useful metadata to be inserted into the P4Info file. Initially, this can be done solely via new @annotations(), without requiring changes to existing P4 compilers. Later we can choose to modify P4 compilers to recognize annotations or other - possibly new - language constructs; or else establish coding conventions and the compiler will populate the P4Info file accordingly. In the meantime, we can experiment with ways to populate proposed new Message elements without modifying p4c.

A utility called xform_anno.py will detect special annotations and transform them into new first-class P4Info protobuf messages or message elements.

See [#275](https://github.com/p4lang/PI/issues/275), [#276](https://github.com/p4lang/PI/issues/276) for background and motivation.

## Highlights
- xform_anno.py - Python script to read P4Info proto file and transform annotations into other protobuf fields
- examples/     - some examples of using the utility

## Annotation transformations
Selected annotations are transformed into proposed, new Message fields and the original annotations are removed.
The new proposed messages are Documentation and PkgInfo (see PI/proto/p4/config/p4info.proto)

 * @brief() is mapped to doc.brief.
 * @description is mapped to doc.description

See **Annotation transform examples** below
## Populating PkgInfo Fields
Currently there is no way to add top-level annotations to P4 code, which would be useful for populating PkgInfo messages (#276). The xform_anno.py utility can be used to populate the PkgInfo message directly from the command-line.

See **Populating PkgInfo from the Command-line** below
# Usage
## Setting up
Prerequisites: p4c-bm2-ss to generate the .proto files from the example P4 source. (see https://github.com/p4lang/p4c)

First, make and install the project per the instructions at the PI top-level README. You have to install the protobuf tools too per those READMEs. Here's how I make the main project:
```
cd PI
./autogen.sh
./configure [--with-bmv2] --with-proto --without-internal-ipc --without-cli
make
sudo make install
cd proto/p4info/xform/examples
```
## Generate P4Info files from your P4 source
Use `gen_p4info.sh` to read P4 source and emit P4Info in three protobuf formats: binary, json and text.
Example:
```
./gen_p4info.sh anno_xform1.p4
```
This results in three new files, automatically named:
```
anno_xform1.p4.p4info.json
anno_xform1.p4.p4info.proto
anno_xform1.p4.p4info.text
```
View the unmodified P4Info files:
```
cat anno_xform1.p4.p4info.txt
cat anno_xform1.p4.p4info.json
cat anno_xform1.p4.p4info.proto | protoc --decode_raw
```
Now play with xform_anno.py per examples below.

## xform_anno.py
### Purpose
The purpose is to convert certain annotations into dedicated protobuf message elements. These elements are proposed enhancements and are not yet produced by the p4c compilers (via --p4runtime-file option). Another feature lets you populate PkgInfo fields direclty from the command-line.
### Quick help
Show help:
```
../xform_anno.py -h
```
Transform P4Info file, output to new file (suitable for a production make rule):
```
../xform_anno.py anno_xform1.p4.p4info.proto out.proto
```
Transform P4Info file, output text; verbose mode enabled to list transformation steps taken (e.g. for development):
```
../xform_anno.py -v -o text anno_xform1.p4.p4info.proto
```
Transform P4Info file (proto format) and emit json:
```
../xform_anno.py -o json anno_xform1.p4.p4info.proto
```
Dry-run with verbose output to see proposed transforms; discard output; verbose messages still visible on stderr:
```
../xform_anno.py -vd -o none anno_xform1.p4.p4info.proto
```
Transform P4Info file, parse result with protoc using raw mode (good to quickly verify encoding or examine output):
```
../xform_anno.py anno_xform1.p4.p4info.proto |protoc --decode_raw
```
Transform P4Info file, parse result with protoc with full decoding. (It's kind of a pain to specify the paths to the .proto file):
```
../xform_anno.py anno_xform1.p4.p4info.proto |protoc -I../../../p4/config --decode=p4.config.P4Info ../../../p4/config/p4info.proto
```
## Annotation transform examples
### Table Entity and match key documentation - @brief(), @description ()
Example P4 code snippet with new `@brief()` and `@description()` annotations for the table and a match key:
```
    @brief("IPv4 LPM lookup brief descrip")
    @description("IPv4 LPM lookup long descrip. Set next hop.")
    @myanno("ipv4_lpm_lkup anno")
    @name(".ipv4_lpm_lkup")
    table ipv4_lpm_lkup {
        actions = {
          @myanno("set_nexthop anno")
            set_nexthop;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm @brief("IPv4 DIP") @description("IPV4 ingress Destination IP Address");
        }
        size = 1024;
        default_action = _drop();
    }
```
Untransformed P4Info with annotations:
```
tables {
  preamble {
    id: 33571990
    name: "ipv4_lpm_lkup"
    alias: "ipv4_lpm_lkup"
    annotations: "@brief(\"IPv4 LPM lookup brief descrip\")"
    annotations: "@description(\"IPv4 LPM lookup long descrip. Set next hop.\")"
    annotations: "@myanno(\"ipv4_lpm_lkup anno\")"
  }
  match_fields {
    id: 1
    name: "hdr.ipv4.dstAddr"
    annotations: "@brief(\"IPv4 DIP\")"
    annotations: "@description(\"IPV4 ingress Destination IP Address\")"
    bitwidth: 32
    match_type: LPM
  }
  ...
```
Transformed P4Info. Notice the `@brief()` and `@description()` annotations are gone, and new `doc` messages appear for the table and the match field:
```
tables {
  preamble {
    id: 33571990
    name: "ipv4_lpm_lkup"
    alias: "ipv4_lpm_lkup"
    annotations: "@myanno(\"ipv4_lpm_lkup anno\")"
    doc {
      brief: "IPv4 LPM lookup brief descrip"
      description: "IPv4 LPM lookup long descrip. Set next hop."
    }
  }
  match_fields {
    id: 1
    name: "hdr.ipv4.dstAddr"
    bitwidth: 32
    match_type: LPM
    doc {
      brief: "IPv4 DIP"
      description: "IPV4 ingress Destination IP Address"
    }
  }
  ...
```
### Action Entity and parameter documentation - @brief(), @description ()
Example P4 code snippet with new `@brief()` and `@description()` annotations for the action and each parameter.
(The code appears cluttered, we need to come up with a nicer way to do this!):
```
    @brief("Set the next hop IP adress and egress port")
    @description("Set the next hop IP adress and egress port longer description")
    @name(".set_nexthop")
    action set_nexthop(
       @brief("Next hop IP address") @description("Next hop IP address longer description") bit<32> nexthop_ipv4,
       @brief("The egress port") @description("The egress port longer description") egress_port_t port)
      {
        meta.routing_metadata.nexthop_ipv4 = nexthop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w63;
    }
```
Untransformed P4Info with annotations:
```
actions {
  preamble {
    id: 16809072
    name: "set_nexthop"
    alias: "set_nexthop"
    annotations: "@brief(\"Set the next hop IP adress and egress port\")"
    annotations: "@description(\"Set the next hop IP adress and egress port longer description\")"
  }
  params {
    id: 1
    name: "nexthop_ipv4"
    annotations: "@brief(\"Next hop IP address\")"
    annotations: "@description(\"Next hop IP address longer description\")"
    bitwidth: 32
  }
  params {
    id: 2
    name: "port"
    annotations: "@brief(\"The egress port\")"
    annotations: "@description(\"The egress port longer description\")"
    bitwidth: 9
  }
}
```
Transformed P4Info. Notice the `@brief()` and `@description()` annotations are gone, and new `doc` messages appear for the action and each parameter:
```
actions {
  preamble {
    id: 16809072
    name: "set_nexthop"
    alias: "set_nexthop"
    doc {
      brief: "Set the next hop IP adress and egress port"
      description: "Set the next hop IP adress and egress port longer description"
    }
  }
  params {
    id: 1
    name: "nexthop_ipv4"
    bitwidth: 32
    doc {
      brief: "Next hop IP address"
      description: "Next hop IP address longer description"
    }
  }
  params {
    id: 2
    name: "port"
    bitwidth: 9
    doc {
      brief: "The egress port"
      description: "The egress port longer description"
    }
  }
}
```
## Populating PkgInfo from the Command-line
For the following examples, we specify the named PkgInfo fields and also add a couple of free-form annotations (meta1, meta2).

Transform a P4Info file and also populate it with PkgInfo message elements from command-line, output to new file (suitable for a production make rule):
```
$ ../xform_anno.py --pkg_name test.p4 --pkg_doc_brief "Test P4Info" --pkg_doc_descr "A longer package description" --pkg_version "1.2.3.4" --pkg_arch "bmv2" --pkg_contact "support@p4.org" --pkg_organization "P4.org" --pkg_url "www.p4.org" --pkg_anno "meta1=value1" --pkg_anno "meta2=value2" anno_xform1.p4.p4info.proto out.proto

```
Transform a P4Info file and also populate it with PkgInfo message elements from command-line, output as text (development):
```
$ ../xform_anno.py -v --pkg_name test.p4 --pkg_doc_brief "Test P4Info" --pkg_doc_descr "A longer package description" --pkg_version "1.2.3.4" --pkg_arch "psa" --pkg_contact "support@p4.org" --pkg_organization "P4.org" --pkg_url "www.p4.org" --pkg_anno "meta1=value1" --pkg_anno "meta2=value2" -o text anno_xform1.p4.p4info.proto
```
Populate PkgInfo message elements from command-line and observe on stdout (no P4Info input file needed). We get the "description" field's text from a file "descrip.txt" which lets us populate it with arbitary long text including newlines.

Here's the description file:
```
$ cat descrip.txt
A long description for the P4Info.
line 2
line 3
line 4
```
Transform the P4Info file and populate PkgInfo:
```
$ ../xform_anno.py -v --pkg_name test.p4 --pkg_doc_brief "Test P4Info" --pkg_doc_descr "`cat descrip.txt`" --pkg_version "1.2.3.4" --pkg_arch "psa" --pkg_contact "support@p4.org" --pkg_organization "P4.org" --pkg_url "www.p4.org" --pkg_anno "meta1=value1" --pkg_anno "meta2=value2" -i none -o text
```
Resulting output from above. Lines starting with +++ are from the -v option and are emitted on stderr. The output below that is the PkgInfo message populated from the command line args.
```
+++ Added pkg_name "test.p4"
+++ Added pkg_version "1.2.3.4"
+++ Added pkg_doc_brief "Test P4Info"
+++ Added pkg_doc_descr "A long description for the P4Info.
line 2
line 3
line 4"
+++ Added pkg_arch "psa"
+++ Added pkg_organization "P4.org"
+++ Added pkg_contact "support@p4.org"
+++ Added pkg_url "www.p4.org"
+++ Added pkg_anno "['meta1=value1', 'meta2=value2']"
pkg_info {
  name: "test.p4"
  version: "1.2.3.4"
  doc {
    brief: "Test P4Info"
    description: "A long description for the P4Info.\nline 2\nline 3\nline 4"
  }
  annotations: "meta1=value1"
  annotations: "meta2=value2"
  arch: "psa"
  organization: "P4.org"
  contact: "support@p4.org"
  url: "www.p4.org"
}
```
### TODO
- Verify transforms for extern doc tags
- Add a file merge option (specify another file to merge into the output). This can be used e.g. to populate PkgInfo from another file.

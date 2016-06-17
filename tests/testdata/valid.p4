// Standard L2 Ethernet header
header_type ethernet_t {
    fields {
        dst_addr        : 48; // width in bits
        src_addr        : 48;
        ethertype       : 16;
    }
}

header ethernet_t ethernet;

header_type h1_t {
    fields {
        f1              : 32;
    }
}

header h1_t h1;

parser start {
    extract(ethernet);
    extract(h1);
    return ingress;
}

action noop() { }

table t1 {
    reads {
        ethernet : valid;
        h1.f1    : valid;
    }
    actions {
        noop;
    }
}

control ingress {
    apply(t1);
}

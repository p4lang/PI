@pragma my_pragma v1
header_type h_t { fields { f32 : 32; } }

@pragma dont_trim
@pragma my_pragma v1
header h_t h;

@pragma dont_trim
@pragma my_pragma v1
header h_t hs[3];

@pragma my_pragma v1
parser_value_set pv;

@pragma my_pragma v1
parser start {
    return select(standard_metadata.ingress_port) {
        pv : ingress;
        default : ingress;
    }
}

@pragma dont_trim
@pragma my_pragma v1
meter m {
    type : packets;
    instance_count : 16;
}

@pragma dont_trim
counter c {
    type : packets;
    instance_count : 16;
}

@pragma dont_trim
@pragma my_pragma v1
register r {
    width : 32;
    instance_count : 16;
}

@pragma my_pragma v1
field_list flist { h.f32; }

@pragma dont_trim
@pragma my_pragma v1
field_list_calculation calc {
    input { flist; }
    algorithm : csum16;
    output_width : 16;
}

@pragma my_pragma v1
action a() { }

@pragma my_pragma v1
table t { actions { a; } }

@pragma my_pragma v1
control ingress { apply(t); }

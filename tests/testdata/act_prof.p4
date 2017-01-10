action a() { }

action_profile ap { actions { a; } size : 128; }

table t1 { action_profile : ap; }
table t2 { action_profile : ap; }

control ingress { apply(t1); apply(t2); }

parser start { return ingress; }

################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2015-2016 Barefoot Networks, Inc.
#
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material is strictly
# forbidden unless prior written permission is obtained from Barefoot Networks,
# Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a
# written agreement with Barefoot Networks, Inc.
#
###############################################################################

from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info

class P4Host(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

    def describe(self):
        print "**********"
        print self.name
        print "default interface: %s\t%s\t%s" %(
            self.defaultIntf().name,
            self.defaultIntf().IP(),
            self.defaultIntf().MAC()
        )
        print "**********"
        
class P4Switch(Switch):
    """P4 virtual switch"""
    device_id = 0

    def __init__( self, name, sw_path = None, json_path = None,
                  thrift_port = None,
                  pcap_dump = False,
                  verbose = False,
                  device_id = None,
                  enable_debugger = False,
                  cpu_port = None,
                  **kwargs ):
        Switch.__init__( self, name, **kwargs )
        assert(sw_path)
        assert(json_path)
        self.sw_path = sw_path
        self.json_path = json_path
        self.verbose = verbose
        logfile = '/tmp/p4s.%s.log' % self.name
        self.output = open(logfile, 'w')
        self.thrift_port = thrift_port
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.cpu_port = cpu_port
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1
        self.nanomsg = "ipc:///tmp/bm-%d-log.ipc" % self.device_id

    @classmethod
    def setup( cls ):
        pass

    def start( self, controllers ):
        "Start up a new P4 switch"
        print "Starting P4 switch", self.name
        args = [self.sw_path]
        # args.extend( ['--name', self.name] )
        # args.extend( ['--dpid', self.dpid] )
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend( ['-i', str(port) + "@" + intf.name] )
        if self.cpu_port:
            args.extend( ['-i', "64@" + self.cpu_port] )
        if self.pcap_dump:
            args.append("--pcap")
        args.append("--log-console")
            # args.append("--useFiles")
        if self.thrift_port:
            args.extend( ['--thrift-port', str(self.thrift_port)] )
        if self.nanomsg:
            args.extend( ['--nanolog', self.nanomsg] )
        args.extend( ['--device-id', str(self.device_id)] )
        P4Switch.device_id += 1
        args.append(self.json_path)
        if self.enable_debugger:
            args.append("--debugger")
        args.append("-- --enable-swap")
        logfile = '/tmp/p4s.%s.log' % self.name
        print ' '.join(args)

        self.cmd( ' '.join(args) + ' >' + logfile + ' 2>&1 &' )
        # self.cmd( ' '.join(args) + ' > /dev/null 2>&1 &' )

        print "switch has been started"

    def stop( self ):
        "Terminate IVS switch."
        self.output.flush()
        self.cmd( 'kill %' + self.sw_path )
        self.cmd( 'wait' )
        self.deleteIntfs()

    def attach( self, intf ):
        "Connect a data port"
        assert(0)

    def detach( self, intf ):
        "Disconnect a data port"
        assert(0)

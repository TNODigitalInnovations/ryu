# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.type_desc import BPFProgram, BPFMatch, ExecBpf
from struct import *

import os

class IcnSdnApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IcnSdnApp, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        print 'packet in'

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        action_controller = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]


        print 'Clearing the flow table'
        datapath.send_msg(self.remove_table_flows(datapath, 0, parser.OFPMatch(), []))


        print 'Transmitting bpf program'
        f = open('match_param_icn.o','r')
        self.send_bpf_program(datapath, 0, f.read())


        print 'Inserting new flows'

        # Match on "tno-1" interest
        # change the destination to unicast address of the other side
        # change the mac to the mac of the default gw

        bpfOfpmatch = BPFMatch(0,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,"tno-1")
        exp_match = parser.OFPMatch( in_port=1,eth_type=0x0800,exec_bpf = bpfOfpmatch)

        actions = []
        actions.append( datapath.ofproto_parser.OFPActionSetField(ipv4_dst="2.0.0.2") )
        actions.append( datapath.ofproto_parser.OFPActionSetField(eth_dst="00:00:00:00:00:01") )
        actions.append( datapath.ofproto_parser.OFPActionOutput(2) )

        self.add_flow(datapath, 1, exp_match, actions)

        
        # return path
	# rewrite the ip address and change the mac to the multicast address

        exp_match = parser.OFPMatch(in_port=2,eth_type=0x0800,ipv4_dst=('2.0.0.1', '255.255.255.255'))

        actions = []
        actions.append( datapath.ofproto_parser.OFPActionSetField(eth_dst="01:00:5e:00:17:aa") )
        actions.append( datapath.ofproto_parser.OFPActionSetField(ipv4_dst="224.0.23.170") )
        actions.append( datapath.ofproto_parser.OFPActionOutput(1) )

        self.add_flow(datapath, 2, exp_match, actions)


        # for the other site

        bpfOfpmatch = BPFMatch(0,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,"tno-2")
        exp_match = parser.OFPMatch(in_port=1,eth_type=0x0800,exec_bpf = bpfOfpmatch)

        actions = []
        actions.append( datapath.ofproto_parser.OFPActionSetField(eth_dst="00:00:00:00:00:02") )
        actions.append( datapath.ofproto_parser.OFPActionSetField(ipv4_dst="2.0.0.1") )
        actions.append( datapath.ofproto_parser.OFPActionOutput(2) )

        self.add_flow(datapath, 3, exp_match, actions)


        # return path

        exp_match = parser.OFPMatch(in_port=2,eth_type=0x0800,ipv4_dst=('2.0.0.2', '255.255.255.255'))

        actions = []
        actions.append( datapath.ofproto_parser.OFPActionSetField(eth_dst="01:00:5e:00:17:aa") )
        actions.append( datapath.ofproto_parser.OFPActionSetField(ipv4_dst="224.0.23.170") )
        actions.append( datapath.ofproto_parser.OFPActionOutput(1) )

        self.add_flow(datapath, 4, exp_match, actions)





    def send_bpf_program(self, datapath, prog_num, bpf_prog):
        print 'sending bpf program'
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        prog_len = len(bpf_prog)

        print "prog len: " + str(prog_len) + "\n"
        print bpf_prog.encode("hex")

        payload = pack("!II" + str(prog_len)  + "s",prog_num,prog_len,bpf_prog)

        print 'payload'
        print payload
        
        msg = parser.OFPExperimenter(datapath=datapath, experimenter=0x66666666,exp_type=0,data=payload)
        
        datapath.send_msg(msg)





    def add_flow(self, datapath, priority, match, actions):
        print 'Flow installed', match
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id, ofproto.OFPFC_DELETE, 0, 0, 1, ofproto.OFPCML_NO_BUFFER, ofproto.OFPP_ANY, ofproto.OFPG_ANY, 0, match, instructions)
        return flow_mod

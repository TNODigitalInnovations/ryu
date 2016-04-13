
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

class AnyMatchSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AnyMatchSwitch, self).__init__(*args, **kwargs)

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

        bpf_match_inport2 = parser.OFPMatch(any_match = BPFProgram((
            ( 0x28, 0, 0, 0x00000000 ),
            ( 0x15, 0, 3, 0x00000200 ), # in_port: 2
            ( 0x28, 0, 0, 0x00000010 ),
            ( 0x15, 0, 1, 0x00000800 ),
            ( 0x6,  0, 0, 0x0000ffff ),
            ( 0x6,  0, 0, 0x00000000 ),
        )))

        bpf_match_inport1 = parser.OFPMatch(any_match = BPFProgram((
            ( 0x28, 0, 0, 0x00000000 ),
            ( 0x15, 0, 3, 0x00000100 ), # in_port: 1
            ( 0x28, 0, 0, 0x00000010 ),
            ( 0x15, 0, 1, 0x00000800 ),
            ( 0x6,  0, 0, 0x0000ffff ),
            ( 0x6,  0, 0, 0x00000000 ),
        )))

	bpf_inport1 = BPFProgram((
            ( 0x28, 0, 0, 0x00000000 ),
            ( 0x15, 0, 3, 0x00000100 ), # in_port: 1
            ( 0x28, 0, 0, 0x00000010 ),
            ( 0x15, 0, 1, 0x00000800 ),
            ( 0x6,  0, 0, 0x0000ffff ),
            ( 0x6,  0, 0, 0x00000000 ),
        ))



        self.send_bpf_program(datapath, 0, bpf_inport1)


        bpfOfpmatch = BPFMatch(0,1,0xFFFFFFFFFFFFFFFF)
        
	exp_match = parser.OFPMatch( exec_bpf = bpfOfpmatch)
	port_match = parser.OFPMatch(in_port = 1)

        print 'Inserting new flows'



        self.add_flow(datapath, 0, port_match, [datapath.ofproto_parser.OFPActionOutput(1)])
        self.add_flow(datapath, 1, exp_match, [datapath.ofproto_parser.OFPActionOutput(1)])
#        self.add_flow(datapath, 0, bpf_match_inport2, [datapath.ofproto_parser.OFPActionOutput(1)])
#        self.add_flow(datapath, 1, bpf_match_inport1, [datapath.ofproto_parser.OFPActionOutput(2)])

#        self.send_experimenter(datapath)



    def send_experimenter(self, datapath):
        print 'sending experimenter'
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
#    uint32_t    prog_id;
#    uint32_t	prog_len;
#    uint8_t * program;


        # prog 1, prog_len 4, ff ff
        payload = bytearray([
         0x00, 0x00, 0x00, 0x00, 
         0x00, 0x00, 0x00, 0x04,
         0xFF, 0xFF, 0xFF, 0xFF
        ])

        msg = parser.OFPExperimenter(datapath=datapath, experimenter=0x66666666,exp_type=0,data=payload)

        datapath.send_msg(msg)


    def send_bpf_program(self, datapath, prog_num, bpf_prog):
        print 'sending bpf program'
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #Join each individual BPF instruction
	bin_bpf_prog= ''.join( [ pack('HBBI', *v) for v in bpf_prog.instructions ]) 
        prog_len = len(bin_bpf_prog)

	print bin_bpf_prog

        payload = pack("!II" + str(prog_len)  + "s",prog_num,prog_len,bin_bpf_prog) 

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

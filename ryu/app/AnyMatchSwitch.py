
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
import time
import json
#from ryu.app.ForwardingMultiSwitch import mac_lookup, route_lookup
from collections import namedtuple
from pyndn import Interest, Name, Blob


from ryu.lib.packet import packet, ethernet, ether_types, ipv4, in_proto as inet, udp

import logging
LOG = logging.getLogger(__name__)

class AnyMatchSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AnyMatchSwitch, self).__init__(*args, **kwargs)
	self.content_learning = {}
	self.program_id = 2
	Router = namedtuple('Router', 'dpid port mac int_ip nat_ip')
	self.routers = {0x01 : Router(0x01, 2, "00:00:0c:9f:f0:16", "134.221.121.1", None), 0x02 : Router(0x02, 2, "52:54:00:12:35:02", "10.0.5.2", "129.82.175.10"), 0x04 : Router(0x04, 2, "52:54:00:12:35:02", "10.0.5.2", "128.117.212.230")} #Config of default gateways
	#self.routers = [Router(0x01, 2, "52:54:00:12:35:02", "129.82.175.1"), Router(0x2, 2, "00:00:0c:9f:f0:16", "134.221.121.1"), Router(0x3, 2, "52:54:00:12:35:02", "134.221.124.1")] #Config of default gateways
	
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        def getName(ndnInterest):
            data = Interest()
            data.wireDecode(ndnInterest)
            return data.getName().toUri()

        msg = ev.msg
        dp = msg.datapath
        dpid = msg.datapath.id
        in_port = msg.match['in_port']
        buffer_id = msg.buffer_id

        ofp = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser  

        if msg.reason == ofp.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofp.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofp.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'
        
        data = msg.data        
        pkt = packet.Packet(data)
        eth = pkt.get_protocol(ethernet.ethernet)
	ip = pkt.get_protocol(ipv4.ipv4)
	dgram = pkt.get_protocol(udp.udp)
	payload = pkt.protocols[-1]

        LOG.debug("AnyMatchSwitch: New incoming packet from %s at switch %d, port %d, for reason %s"%(eth.src,dpid,in_port,reason))

	#Routing packet from publish-local-content
	if eth.dst == "01:00:5e:00:17:aa" and eth.ethertype == ether_types.ETH_TYPE_IP and ip.dst == "224.0.23.170" and ip.proto == inet.IPPROTO_UDP and dgram.dst_port == 46363:
		LOG.warn("AnyMatchSwitch: Accepted incoming packet from %s at switch %d, port %d, for reason %s"%(eth.src,dpid,in_port,reason))
	        LOG.debug("\t%s"%(msg))        
        	LOG.debug("\t%s"%(pkt))
		LOG.debug("\tJSON string: %s"%(payload,))
		content_list = json.loads(payload)
		for content_dict in content_list:
			name = content_dict["name"]
			cost = content_dict["cost"]
			ContentLocation = namedtuple('ContentLocation', 'name dpid port mac ip')

			cl = ContentLocation(name = name, dpid = dpid, port = in_port, mac = eth.src, ip = ip.src)
			LOG.warn("\t\tName lookup %s"%(cl,))
			self.content_learning[cl] = cost

	#ICN Multicast packet
	elif eth.dst == "01:00:5e:00:17:aa" and eth.ethertype == ether_types.ETH_TYPE_IP and ip.dst == "224.0.23.170" and ip.proto == inet.IPPROTO_UDP and dgram.dst_port == 56363:
		LOG.warn("AnyMatchSwitch: Accepted incoming packet from %s at switch %d, port %d, for reason %s"%(eth.src,dpid,in_port,reason))
		name = getName(Blob(payload))
		LOG.warn("\tInterest received, name: %s"%(name,))
		cls = [cl for cl in self.content_learning if name == cl.name or name.startswith(cl.name+"/")]
		lpm_cl = max(cls, key=lambda _cl: len(_cl.name)) #Longest prefix match, ToDo: include routing cost to find closest of potentially multiple lpms
		key = str(lpm_cl.name.split("/")[1]) #ToDo: extend this line and the eBPF program to accept full NDN URIs instead of just the first name component
		LOG.warn("\tToDo: Extend the eBPF to support multiple namecomponents, for now: key=%s"%(key,))

		##Select routers in domain, if any, !!!!! Some problems arise with route_lookup event..., haven't solved yet.
		#_routers = [(router, route_lookup(self, dpid, router.dpid)) for router in self.routers]
		#routers = [(router, route) for (router, route) in _routers if route.cost is not None]
		#if len(routers) == 0:
		#	LOG.warn("\tNo routers found in domain")
		#	return

		#Find closest-by router based on route_lookup cost and determine whether to use internal or NAT ip address
		#router, route = min([(router, route) for (router,route) in routers], key=lambda (_router, _route): _route.cost)
		#nexthop, port = route.fw

		#But first, simple one router per switch solution
		router_dpid = [router_dpid for router_dpid in self.routers if router_dpid == dpid][0]
		router = self.routers[router_dpid]
		port = router.port
		

		bpfOfpmatch = BPFMatch(self.program_id,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,key)
		exp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x11, udp_dst=56363, exec_bpf=bpfOfpmatch)
		LOG.warn("\t\tAdding match rule for key %s"%(key,))
		dst_ip = lpm_cl.ip
		if lpm_cl.dpid in self.routers and self.routers[lpm_cl.dpid].nat_ip is not None:
			dst_ip = self.routers[lpm_cl.dpid].nat_ip
		actions = [dp.ofproto_parser.OFPActionSetField(ipv4_dst=dst_ip),
			dp.ofproto_parser.OFPActionSetField(udp_dst=6363),
			dp.ofproto_parser.OFPActionSetField(udp_src=6363),
			dp.ofproto_parser.OFPActionSetNwTtl(128),
			dp.ofproto_parser.OFPActionSetField(eth_dst=router.mac),
			dp.ofproto_parser.OFPActionOutput(port)]
		
		self.add_flow(dp, 10, exp_match, actions)

		#Send barrier-message to ensure execution of previous rule before output action.
		#req = parser.OFPBarrierRequest(dp)
		#dp.send_msg(req)
		
		#Output first packet
		ports = [port]
		LOG.warn("\tToDo: replace with the output-function from ForwardingMultiSwitch for code maintainability.")
		#actions = [parser.OFPActionOutput(port, 0) for port in ports]

		if buffer_id != None:
			LOG.warn("\t\tOutputting via buffer_id on switch %d ports %s"%(dpid, ports))
			req = parser.OFPPacketOut(dp, buffer_id = buffer_id, in_port=in_port, actions=actions)
			dp.send_msg(req)

		#Forward packet through data-field.
		elif len(actions)>0:
			LOG.warn("\t\tOutputting on outgoing switch %d ports %s"%(dpid, ports))
			req = parser.OFPPacketOut(dp, buffer_id = ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=data)
			dp.send_msg(req)
		else:
			LOG.warn("\t\tDropped by definition due to no output-ports nor buffer_id")
	#Otherwise
	else:
		LOG.debug("\t Ignored, not our packet")
		return

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def switch_state_change_handler(self, ev):
        LOG.warn("AnyMatchSwitch: Entered MAIN State")

        datapath = ev.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        action_controller = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        f = open('match_param_icn.o','r')
        self.send_bpf_program(datapath, self.program_id, f.read())

    def send_bpf_program(self, datapath, prog_num, bpf_prog):
        LOG.warn("AnyMatchSwitch: Sending bpf program")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        prog_len = len(bpf_prog)

        LOG.warn("\tProgram length: %d"%(prog_len,))
        LOG.warn("\t\t %s"%(bpf_prog.encode("hex"),))

        payload = pack("!II" + str(prog_len)  + "s",prog_num,prog_len,bpf_prog) 

        LOG.warn("\tPayload: %s"%(payload,))

        msg = parser.OFPExperimenter(datapath=datapath, experimenter=0x66666666,exp_type=0,data=payload)
        datapath.send_msg(msg)

    def add_flow(self, datapath, priority, match, actions):
        LOG.warn("AnyMatchSwitch: Flow installed %s"%(match,))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

app_manager.require_app('ryu.app.ForwardingMultiSwitch')


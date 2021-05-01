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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet import bgp

import os
import sys

from topoutils.topology_utils import Signal_Detector, Shift_Rule, Quarantined_Announcement, Blocked_Announcement, Monitor_TCP_Flow

from ryu.lib import hub

import time 

import array
import pprint

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.Router_routing_table = {}
        self.Delayed_BGP_packets = []
        self.delay_timer = 1800 # seconds
        self.TCP_Shifting_Rules = []
        self.target_number_of_shifted_packets = 1
        self.blocked_routes = []
        self.OoO_Freq_Dict = {}
        self.TCP_flows = []
        self.Signal_Detector = Signal_Detector(SIGNAL_THRESHOLD = 10)
    
    def delay_bgp_packet(self, out, prefix, origin_as):
        ts = int(time.time())
        delayed_packet = Quarantined_Announcement(out, ts, prefix, origin_as)
        self.Delayed_BGP_packets.append(delayed_packet)
        return
    
    def check_delayed_packets(self):
        ts = int(time.time())
        for delayed in self.Delayed_BGP_packets:
            delayed_ts = delayed.timestamp
            if ts - delayed_ts >= self.delay_timer:
                print("Sending delayed packet...")
                self.Delayed_BGP_packets.remove(delayed)
                out = delayed.out
                datapath = out.datapath
                datapath.send_msg(out)

                # Remove flow shifting rule for this dest
                delayed_prefix = delayed.prefix
                for flow_rule in self.TCP_Shifting_Rules:
                    if flow_rule.prefix == delayed_prefix:
                        self.TCP_Shifting_Rules.remove(flow_rule)
                        break

                # Add routing paths to table
                pkt = packet.Packet(out.data)
                bgp_packets = pkt.get_protocols(bgp.BGPMessage)
                for bgp_message in bgp_packets:
                    self.add_prefix_route(bgp_message)
                pprint.pprint(self.Router_routing_table, width=1)
                print("-------------------------------------")
        return 

    def block_route_for_signal(self, signal):
        for shift_rule in self.TCP_Shifting_Rules:
            if signal == shift_rule.amount:
                blocked_prefix = shift_rule.prefix
                as_source = signal

                self.TCP_Shifting_Rules.remove(shift_rule)

                for delayed in self.Delayed_BGP_packets:
                    if delayed.origin_as == signal:
                        self.Delayed_BGP_packets.remove(delayed)
                
                blocked_announcement = Blocked_Announcement(prefix = blocked_prefix, as_source = as_source)
                self.blocked_routes.append(blocked_announcement)



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def get_path_origin_as(self, as_path):
        return as_path[-1]
    
    def add_prefix_route(self, bgp_message):
        path_attrs = bgp_message.path_attributes
        for attr in path_attrs:
            if isinstance(attr, bgp.BGPPathAttributeAsPath):
                as_paths = attr.value
                break
        message_nlris = bgp_message.nlri 
        for bgpnlri in message_nlris:
            if isinstance(bgpnlri, bgp.BGPNLRI):
                prefix = bgpnlri.addr
                if prefix not in self.Router_routing_table:
                    self.Router_routing_table[prefix] = []
                for route in as_paths:
                    self.Router_routing_table[prefix].append(route)
        return 
    
    def withdraw_route(self, withdrawn_as, prefix):
        for route in self.Router_routing_table[prefix]:
            if route[0] is withdrawn_as:
                print("Withdrawn prefix %s from AS: %s"%(prefix, withdrawn_as))
                self.Router_routing_table[prefix].remove(route)
        return 
        
    def check_if_route_is_blocked(self, bgp_message):
        path_attrs = bgp_message.path_attributes
        for attr in path_attrs:
            if isinstance(attr, bgp.BGPPathAttributeAsPath):
                as_paths = attr.value
                break

        origin_as = self.get_path_origin_as(as_paths[0])

        message_nlris = bgp_message.nlri

        for bgpnlri in message_nlris:
            if isinstance(bgpnlri, bgp.BGPNLRI):
                prefix = bgpnlri.addr
                for blocked_announcement in self.blocked_routes:
                    if blocked_announcement.prefix == prefix and blocked_announcement.as_source == origin_as:
                        return True
        return False

    def accept_route(self, bgp_message):
        new_origin_as = -1
        prefix = '0.0.0.0/0'
        path_attrs = bgp_message.path_attributes
        for attr in path_attrs:
            if isinstance(attr, bgp.BGPPathAttributeAsPath):
                as_paths = attr.value
                break

        message_nlris = bgp_message.nlri

        for bgpnlri in message_nlris:
            if isinstance(bgpnlri, bgp.BGPNLRI):
                prefix = bgpnlri.addr
                if prefix in self.Router_routing_table:
                    existing_origin_as = self.get_path_origin_as(self.Router_routing_table[prefix][0])
                    new_origin_as = self.get_path_origin_as(as_paths[0])
                    # Delay condition
                    if existing_origin_as is not new_origin_as:
                        print("Delaying packet for %s from AS %s"%(prefix, new_origin_as))
                        # os.system("rm scenario-stats/curl-stats-before-validation.txt")
                        # os.system("cp curl-stats.txt scenario-stats/curl-stats-before-validation.txt")
                        # os.system("rm curl-stats.txt")
                        return False, new_origin_as, prefix
        return True, new_origin_as, prefix
    

    def shift_tcp_flow(self, flow_dest, shift_amount):
        shift_rule = Shift_Rule(prefix = flow_dest, 
                                amount = shift_amount, 
                                counter = 0, 
                                target = self.target_number_of_shifted_packets)
        self.TCP_Shifting_Rules.append(shift_rule)
        return

    # Returns True if dst_ip is in the destination prefix
    # Eg. 11.0.0.1 in 11.0.0.0/8 TRUE
    #     12.0.0.1 in 11.0.0.0/8 FALSE
    def ip_in_prefix(self, dst_ip, dst_prefix):
        dst_ip = dst_ip.split('.')
        dst_prefix = dst_prefix.split('.')
        return dst_ip[0] == dst_prefix[0]
    
    def must_shift_payload(self, src_ip, dst_ip, shift_rule, dst_port, src_port):
        # destination prefix for which packets should be shifted
        shift_dst = shift_rule.prefix

        # if the packet destination IPv4 is not in the prefix
        if not self.ip_in_prefix(dst_ip = dst_ip, dst_prefix = shift_dst):
            return False
        
        # checks if enough packets have beenn shifted for this flow 
        if not shift_rule.can_shift_packet_for_flow(src_ip, dst_ip, dst_port, src_port):
            return False
        return True
    
    def ignore_bgp_retransmission(self, pkt):
        tcp_header = pkt.get_protocol(tcp.tcp)

        # don't ignore if not BGP
        if not (tcp_header is not None and (tcp_header.src_port == 179 or tcp_header.dst_port == 179)):
            return False
        
        bgp_packets = pkt.get_protocols(bgp.BGPMessage)
        for bgp_message in bgp_packets:
            if isinstance(bgp_message, bgp.BGPUpdate) and len(bgp_message.path_attributes) > 0:
                path_attrs = bgp_message.path_attributes
                for attr in path_attrs:
                    if isinstance(attr, bgp.BGPPathAttributeAsPath):
                        as_path = attr.value[0]
                        break

                message_nlris = bgp_message.nlri

                for bgpnlri in message_nlris:
                    if isinstance(bgpnlri, bgp.BGPNLRI):
                        prefix = bgpnlri.addr
                        for delayed in self.Delayed_BGP_packets:
                            if delayed.prefix == prefix and delayed.get_as_path() == as_path:
                                return True
        return False
    
    def check_for_signal(self):
        detector = self.Signal_Detector
        freq_dict = self.OoO_Freq_Dict
        amount = 0
        if detector.has_received_signal(freq_dict):
            amount = detector.get_outlier(freq_dict)
            # refresh OoO Frequency Dict
            self.OoO_Freq_Dict = {}
            # Add shifting rule
            return True, amount
        else:
            return False, amount


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        self.check_delayed_packets()

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            # data = msg.data
            data = pkt.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        tcp_header = pkt.get_protocol(tcp.tcp)
        pkt_ipv4   = pkt.get_protocol(ipv4.ipv4)
        
        
        
        if in_port < out_port:
            received_message = True
            # check if incoming message is a retransmission for a quarantined bgp announcement
            if self.ignore_bgp_retransmission(pkt):
                return
        else:
            received_message = False
        

        if tcp_header is not None and received_message == True:
            for shift_rule in self.TCP_Shifting_Rules:
                if tcp_header.has_flags(0x001): # FIN Flag
                    shift_rule.remove_flow(pkt_ipv4.src, pkt_ipv4.dst, tcp_header.dst_port, tcp_header.src_port)
        
        # Check for BGP Message
        if (tcp_header is not None and (tcp_header.src_port == 179 or tcp_header.dst_port == 179)):
            route_accepted = True
            # Get all BGP packets sent using the Transport Control Protocol
            bgp_packets = pkt.get_protocols(bgp.BGPMessage)
            for bgp_message in bgp_packets:
                if isinstance(bgp_message, bgp.BGPUpdate):

                    # Check for withdrawn routes:
                    if len(bgp_message.withdrawn_routes) > 0 and received_message is True:   
                        # dpid = 84 / 83
                        withdrawn_as = dpid%10
                        
                        # Get withdrawn prefixes
                        print("BGP Withdrawn Routes\n")
                        withdrawn_routes = bgp_message.withdrawn_routes
                        for route in withdrawn_routes:
                            if isinstance(route, bgp.BGPWithdrawnRoute):
                                withdrawn_prefix = route.addr
                                self.withdraw_route(withdrawn_as, withdrawn_prefix)
                                break
                        pprint.pprint(self.Router_routing_table, width=1)
                        print("-------------------------------------")

                    # Incoming Route Announcement
                    if len(bgp_message.path_attributes) > 0 and received_message is True:
                        print("BGP Route Announcement\n")
                        
                        # Check for blacklisted announcements
                        if self.check_if_route_is_blocked(bgp_message):
                            # Route is blocked
                            print("Dropping BLOCKED route.")
                            return

                        route_accepted, new_origin_as, prefix = self.accept_route(bgp_message)

                        if route_accepted:
                            self.add_prefix_route(bgp_message)
                            pprint.pprint(self.Router_routing_table, width=1)
                            print("-------------------------------------")
                        else:
                            self.delay_bgp_packet(out, prefix, new_origin_as)
                            self.shift_tcp_flow(flow_dest = prefix, shift_amount = new_origin_as)

            if route_accepted is True:
                datapath.send_msg(out)
        # Check for tcp shifting for outgoing traffic 
        elif tcp_header is not None and received_message == False:
            for shift_rule in self.TCP_Shifting_Rules:
                # how much does the payload needs to be shifted by
                shift_amount = shift_rule.amount

                # If outgoing traffic matches quarantined destination for which
                # the SEQ / Payload must be shifted
                if not isinstance(pkt.protocols[-1], bytes):
                    continue
                if self.must_shift_payload(src_ip = pkt_ipv4.src,
                                            dst_ip = pkt_ipv4.dst, 
                                            shift_rule = shift_rule, 
                                            dst_port = tcp_header.dst_port,
                                            src_port = tcp_header.src_port):                            
                    print("Inform Victim. Shifting TCP payload by %d"%(shift_amount))
                    new_pkt = packet.Packet()
                    for prt in pkt.protocols:
                        # ethernet
                        if isinstance(prt, ethernet.ethernet):
                            new_pkt.add_protocol(prt)
                        # ipv4
                        elif isinstance(prt, ipv4.ipv4):
                            ip4 = ipv4.ipv4(version=prt.version,
                                            header_length=prt.header_length,
                                            tos=prt.tos,
                                            total_length=prt.total_length - shift_amount, # adjust 
                                            identification=prt.identification,
                                            flags=prt.flags,
                                            offset=prt.offset,
                                            ttl=prt.ttl,
                                            proto=prt.proto,
                                            csum=0,
                                            src=prt.src,
                                            dst=prt.dst,
                                            option=prt.option
                                            )
                            new_pkt.add_protocol(ip4)
                        elif isinstance(prt, tcp.tcp):
                            # change tcp header
                            t = tcp.tcp(src_port = prt.src_port,
                                        dst_port = prt.dst_port,
                                        seq = prt.seq + shift_amount, #shift 
                                        # seq = proto.seq,
                                        ack = prt.ack, 
                                        offset = prt.offset, # this is wrong
                                        bits = prt.bits,
                                        window_size = prt.window_size,
                                        csum = 0,
                                        urgent = prt.urgent,
                                        option = prt.option)
                            new_pkt.add_protocol(t)
                        elif isinstance(prt, bytes):
                            payload = prt
                            # TODO: check if payload has at least shift_amount bytes ...
                            new_pkt.add_protocol(payload[shift_amount:])
                        # ethernet, ipv4, ...
                        else:
                            new_pkt.add_protocol(prt)
                    new_pkt.serialize()
                    out.data = new_pkt.data

                    # update counter for number of shifted packets on this flow 
                    shift_rule.shifted_flow(pkt_ipv4.src, pkt_ipv4.dst, tcp_header.dst_port, tcp_header.src_port)
                    # for rule in self.TCP_Shifting_Rules:
                    #     print(rule)
            datapath.send_msg(out)
        else:
            datapath.send_msg(out)
        
        # If there is a quarantined route for which the sentinel is waiting for a signal
        if len(self.Delayed_BGP_packets) > 0:
            if tcp_header is not None and tcp_header.has_flags(0x001): # FIN Flag
                src_ip = pkt_ipv4.src
                dst_ip = pkt_ipv4.dst
                src_port = tcp_header.src_port
                dst_port = tcp_header.dst_port
                this_flow = Monitor_TCP_Flow(src_ip, dst_ip, src_port, dst_port)
                for flow in self.TCP_flows:
                    # flow already recorded, update expected seq 
                    if this_flow == flow:
                        self.TCP_flows.remove(flow)
                        break
            if tcp_header is not None and received_message:
                src_ip = pkt_ipv4.src
                dst_ip = pkt_ipv4.dst
                src_port = tcp_header.src_port
                dst_port = tcp_header.dst_port
                this_flow = Monitor_TCP_Flow(src_ip, dst_ip, src_port, dst_port)
                # flow already recorded
                if isinstance(pkt.protocols[-1], bytes): # python3 expects bytes instead of str
                    payload = pkt.protocols[-1]
                    for flow in self.TCP_flows:
                        # flow already recorded, update expected seq 
                        if this_flow == flow:
                            seq_diff = flow.update_expected_seq(tcp_header.seq, len(payload))
                            # seq unexpected
                            if seq_diff != 0:
                                if seq_diff in self.OoO_Freq_Dict:
                                    self.OoO_Freq_Dict[seq_diff] += 1
                                else:
                                    self.OoO_Freq_Dict[seq_diff] = 1
                                print("Out-of-Order Frequency Dictionary")
                                pprint.pprint(self.OoO_Freq_Dict)
                            break
                # new flow
                elif tcp_header.has_flags(tcp.TCP_SYN): # doesn't necessarily have to have SYNACK - it could be incoming flow (will just have SYN...)
                    this_flow.update_expected_seq(tcp_header.seq + 1, 0)
                    self.TCP_flows.append(this_flow)

            received_signal, signal = self.check_for_signal()
            if received_signal:
                print("Blocking route for signal: %d"%(signal))
                # os.system("echo \"Validation Process Completion Time: `date`\" >> scenario-stats/eval-detection-timestamps.txt")
                # os.system("cp curl-stats.txt scenario-stats/curl-stats-during-validation.txt")
                self.block_route_for_signal(signal)

        

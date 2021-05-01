from __future__ import division

from ryu.lib.packet import packet
from ryu.lib.packet import bgp
from numpy import mean, std
import json

class TCP_Flow:
    def __init__(self, src_ip, dst_ip, dst_port, src_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_port = src_port
        self.counter_shifted_packets = 0
    
    def __eq__(self, other):
        if isinstance(other, TCP_Flow):
            return self.src_ip == other.src_ip and \
                    self.dst_ip == other.dst_ip and \
                    self.dst_port == other.dst_port and \
                    self.src_port == other.src_port
        return False
    
    def __str__(self):
        return ("\t SRC ip = %s(p = %s) DST ip = %s(p = %s) shft = %d\n"%(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.counter_shifted_packets))

    
    def increase_counter(self):
        self.counter_shifted_packets += 1

class Shift_Rule:
    def __init__(self, prefix, amount, counter, target):
        self.prefix = prefix
        self.amount = amount
        self.flows = []
        self.target_shifted_packets_per_flow = target
    
    def __eq__(self, other):
        if isinstance(other, Shift_Rule):
            return self.prefix == other.prefix and \
                self.amount == other.amount
        return False
    
    def __str__(self):
        res = ''
        title = "prefix = %s\namount = %s\n"%(self.prefix, self.amount)
        res += title
        for flow in self.flows:
            res += str(flow)
        return res
   
    def can_shift_packet_for_flow(self, src_ip, dst_ip, dst_port, src_port):
        this_flow = TCP_Flow(src_ip, dst_ip, dst_port, src_port)
        for flow in self.flows:
            # only checks if dst and src ports are the same
            if flow == this_flow:
                if flow.counter_shifted_packets >= self.target_shifted_packets_per_flow:
                    return False
                else:
                    flow.increase_counter()
                    return True
        return True
    
    def shifted_flow(self, src_ip, dst_ip, dst_port, src_port):
        this_flow = TCP_Flow(src_ip, dst_ip, dst_port, src_port)
        for flow in self.flows:
            if this_flow == flow:
                flow.increase_counter()
                return
        this_flow.increase_counter()
        self.flows.append(this_flow)
        return
    
    def remove_flow(self, src_ip, dst_ip, dst_port, src_port):
        this_flow = TCP_Flow(src_ip, dst_ip, dst_port, src_port)
        for flow in self.flows:
            if this_flow == flow:
                self.flows.remove(flow)
                break
        return 

class Blocked_Announcement:
    def __init__(self, prefix, as_source):
        self.prefix = prefix
        self.as_source = as_source
    
    def __eg__(self, other):
        if isinstance(other, Blocked_Announcement):
            return self.prefix == other.prefix and \
                    self.as_source == other.as_source
        return False

class Quarantined_Announcement:
    def __init__(self, out, timestamp, prefix, origin_as):
        self.out = out
        self.timestamp = timestamp
        self.prefix = prefix
        self.origin_as = origin_as
    
    def __eq__(self, other):
        if isinstance(other, Quarantined_Announcement):
            return self.out == other.out and \
                self.timestamp == other.timestamp and \
                self.prefix == other.prefix
        return False
    
    def get_as_path(self):
        pkt = packet.Packet(self.out.data)
        bgp_packets = pkt.get_protocols(bgp.BGPMessage)
        for bgp_message in bgp_packets:
            if isinstance(bgp_message, bgp.BGPUpdate) and len(bgp_message.path_attributes) > 0:
                path_attrs = bgp_message.path_attributes
                for attr in path_attrs:
                    if isinstance(attr, bgp.BGPPathAttributeAsPath):
                        return attr.value[0]
        return None

class Monitor_TCP_Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.expected_seq = []

    
    def __eq__(self, other):
        if isinstance(other, Monitor_TCP_Flow):
            return self.src_ip == other.src_ip and \
                    self.dst_ip == other.dst_ip and \
                    self.dst_port == other.dst_port and \
                    self.src_port == other.src_port
        return False
    
    def __str__(self):
        return ("\t SRC ip = %s(p = %s) DST ip = %s(p = %s) exp_seq = %s\n"%(self.src_ip, 
                self.src_port, 
                self.dst_ip, 
                self.dst_port, 
                str(self.expected_seq)))
    
    # returns -1 if unexpected seq, 0 otherwise
    def update_expected_seq(self, seq, payload_len):
        if len(self.expected_seq) == 0:
            self.expected_seq.append(seq + payload_len)
            return 0
        else:
            # if in order
            if seq in self.expected_seq:
                self.expected_seq.remove(seq)
                self.expected_seq.append(seq + payload_len)
                return 0
            else:
                # out of order
                seq_diff = seq - self.expected_seq[0]
                self.expected_seq.append(seq + payload_len)
                return seq_diff
        return 0


class Signal_Detector:

    def __init__(self, SIGNAL_THRESHOLD):
        self.SIGNAL_THRESHOLD = SIGNAL_THRESHOLD
        self.outlier = 0

    def has_received_signal(self, freq_dict):
        data = []
        for key, value in freq_dict.items():
            data.append(value)
        if len(data) == 0:
            return False
        if max(data) < self.SIGNAL_THRESHOLD:
            return False
        
        if len(freq_dict) == 1:
            self.outlier = list(freq_dict.keys())[0]
            return True
        
        if len(freq_dict) == 2:
            max_freq = 0
            max_amount = 0
            for key, value in freq_dict.items():
                if value > max_freq:
                    max_freq = value
                    max_amount = key
            self.outlier = max_amount
            return True
        
        # Set upper and lower limit to 2 standard deviation
        data = []
        for key, value in freq_dict.items():
            data.append(value)
        
        data_std = std(data)
        data_mean = mean(data)
        anomaly_cut_off = data_std * 2

        lower_limit  = data_mean - anomaly_cut_off 
        upper_limit = data_mean + anomaly_cut_off

        # Generate outliers
        for key, value in freq_dict.items():
            if value > upper_limit or value < lower_limit:
                self.outlier = key
                return True
                return key < 10

        return False


    # Function to Detection Outlier on one-dimentional datasets.
    # Returns the encoded shift amount in the flow 
    def get_outlier(self, freq_dict):

        return self.outlier


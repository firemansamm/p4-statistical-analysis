import nnpy
import struct
import termcolor as T
import operator
import time
import threading

from scapy.layers.l2 import Ether
from scapy.layers import inet
from scapy.contrib import bgp

# Quagga BGPd uses 4 bytes ASNs.
bgp.bgp_module_conf.use_2_bytes_asn = False

from pypacker import psocket
#from pypacker.layer12 import ethernet
#from pypacker.layer3 import ip
#from pypacker.layer4 import tcp
#from pypacker.layer567 import bgp


from numpy import std, mean
from sswitch_API import SimpleSwitchAPI

_THRIFT_PORT = 22223
_SIGNAL_THRESHOLD = 10
_RULE_EXPIRATION_SEC = 900
_QUARANTINE_EXPIRATION_SEC = 300
_DO_LOG = True
_CPU_PORT_VETH = 'veth251'
AS_PATH = 2
AS_SEQUENCE = 2


if _DO_LOG:
    def log(s, col="green"):
        print(T.colored(s, col))
else:
    def log(s, col):
        pass

class Controller(object):
    def __init__(self):
        self.controller = SimpleSwitchAPI(_THRIFT_PORT)
        self.controller.reset_state()
        self.seq_dict = {}
        self.slice_rules = {}
        self.last_free_counter = 0
        self.allocated_counters = []
        self.running = True

        # Remove the CPU port from multicast
        ports = [port for port in self.controller.client.bm_dev_mgr_show_ports() if port.port_num != 255] 
        mc_grp_id = 1
        rid = 0
        for port in ports:
            other_ports = ports[:] # clone the port
            del(other_ports[other_ports.index(port)])
            self.controller.mc_mgrp_create(mc_grp_id)
            handle = self.controller.mc_node_create(rid, [p.port_num for p in other_ports])
            self.controller.mc_node_associate(mc_grp_id, handle)
            self.controller.table_add("multicast", "set_mcast_grp", [str(port.port_num)], [str(mc_grp_id)])
            rid += 1
            mc_grp_id += 1

    def on_notify(self, msg):
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                    msg[:32])
        self.process_digest(msg, num)
        # Acknowledge
        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def add_slice(self, prefix, n):
        prefix_str = "{}.0.0.0/8".format(prefix)
        log("sending slice for LPM {}...".format(prefix_str), "red")
        rule_handle = self.controller.table_add("respondBgp", "slice", [prefix_str], [str(n)]) # slice in bits 
        self.slice_rules[int(prefix)] = {'handle': rule_handle, 'expiration': int(time.time()) + _RULE_EXPIRATION_SEC} 

    def process_digest(self, msg, num_samples):
        log("digest incoming!")
        digest = []
        offset = 32
        for _ in range(num_samples):
            if msg[offset] == 0:
                mac0, mac1, ingress_port = struct.unpack(">LHH", msg[offset + 1:offset+9])
                mac_addr = hex((mac0 << 16) + mac1)
                log("learn {} on {}".format(mac_addr, ingress_port))
                self.controller.table_add("source", "NoAction", [str(mac_addr)], [])
                self.controller.table_add("dest", "forward", [str(mac_addr)], [str(ingress_port)])
                offset += 9
            elif msg[offset] == 1:
                expected, got, prefix = struct.unpack(">LLc", msg[offset+1 : offset+10])
                log("received seq update!")
                gap = got - expected
                log("gap = {}, prefix = {}".format(gap, int(prefix[0])))
                # Check for existing quarantined packets with this gap value.
                r = int(prefix[0])
                if (gap, str(r)) in self.quarantined:
                    log("Received response for prefix {}, blocking AS {}.".format(r, gap), "red")
                    del self.quarantined[(gap, str(r))]
                    # Delete slice rule.
                    self.controller.table_delete("respondBgp", self.slice_rules[r]['handle'])
                    del self.slice_rules[r]
                else:
                    log("Could not find any quarantined for AS {} (prefix {}.0.0.0/8).".format(gap, r), "yellow")

                offset += 10
            elif msg[offset] == 2:
                prefix = msg[offset + 1]
                if not prefix in self.allocated_counters:
                    log('allocating prefix {} to counter {}'.format(prefix, self.last_free_counter))
                    pfx_str = "{}.0.0.0/8".format(prefix)
                    self.controller.table_add("seqprefix", "set_counter_idx", [pfx_str], [str(self.last_free_counter)])
                    self.last_free_counter += 1
                    self.allocated_counters.append(prefix)
                offset += 5
            else:
                log('unknown digest type {}'.format(msg[offset]))
        return digest

    # cleans up expired rules every 10 seconds and doesn't ever return.
    def do_expired_rule_cleanup(self):
        while self.running:
            expired_rules = [rule for rule in self.slice_rules.keys() if self.slice_rules[rule]['expiration'] < int(time.time())]
            for r in expired_rules:
                log("deleting expired rule for prefix={}.0.0.0/8".format(r))
                self.controller.table_delete("respondBgp", self.slice_rules[r]['handle'])
                del self.slice_rules[r]

                qkey = [(q, k) for (q, k) in self.quarantined.keys() if k == r]
                if len(qkey) == 0:
                    log("couldn't find a quarantine key matching this prefix...", "yellow")
                    continue
                self.allowed.append(qkey[0])
            time.sleep(10)

    def await_notifications(self):
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        sock = self.controller.client.bm_mgmt_get_info().notifications_socket
        log("socket = {}".format(sock))
        sub.connect(sock)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
        log("connected to socket.")

        while True:
            self.on_notify(sub.recv())

    def cpu_port_handler(self, packet, psock):
        eth = Ether(packet)
        if not self.running:
            raise Exception('stop')

        if not eth.haslayer(bgp.BGPUpdate):
            # Release the packet.
            psock.send(packet)
            return

        #log("Get BGP update packet: {}".format(eth.summary()), "yellow")

        update = eth[bgp.BGPUpdate]

        # Flag to determine whether this packet should be stopped.
        quarantine = False
        drop = False
        quarantine_key = None

        while True:
            # Check if this path_attr ends at a different AS compared to 
            # known for this prefix, and if so, quarantine this BGP update packet.
            
           
            p = [path_attr for path_attr in update.path_attr if path_attr.type_code == AS_PATH]
            if len(p) > 0:
                s = [path.segment_value for path in p[0].attribute.segments if path.segment_type == AS_SEQUENCE]
                if len(s) > 0:
                    # Get the destination AS in each sequence. Assert that they are all the same.
                    dest = [seq[-1] for seq in s]
                    assert(all(d == dest[0] for d in dest))
                    if dest[0] in self.blocked_as:
                        log("Dropping packet announcing blocked AS {}.".format(dest[0]), "red")
                        drop = True
                        break
                    if dest[0] != 0:
                        for dest_prefix in [nlri.prefix for nlri in update.nlri]:
                            #print("Announcement for prefix {}:".format(dest_prefix))
                            #print(s)
                            if dest_prefix.split('.')[0] == 9:
                                continue # TODO: this skips the internal network. Should be fixed with CIDR below.
                            if (dest[0], dest_prefix.split('.')[0])  in self.quarantined:
                                drop = True # Ignore this packet that's advertising a quarantined route.
                            elif dest_prefix in self.routing_table and self.routing_table[dest_prefix] != dest[0]:
                                log("Delay AS {} announcing prefix {}.".format(dest[0], dest_prefix), "red")

                                # Ideally, we should look through all of the updates and notify all the 
                                # ASes being targeted in a single update. For now though, we only notify
                                # the first, and similarly unblock the AS when this is done.
                                
                                # Hardcode the prefix to /8. This needs modification on the P4 side to support 
                                # proper CIDR.
                                quarantine_key = (dest[0], dest_prefix.split('.')[0])
                                if not quarantine_key in self.allowed:
                                    quarantine = True
                                break
                            else:
                                log("Route {}: {}".format(dest_prefix, s[0]))
                                self.routing_table[dest_prefix] = dest[0]

            if not update.haslayer(bgp.BGPHeader) or not update[bgp.BGPHeader].haslayer(bgp.BGPUpdate):
                break
            else:
                # next update
                update = update[bgp.BGPHeader][bgp.BGPUpdate]
        
        if drop:
            pass # blackhole
        elif not quarantine:
            psock.send(packet)
        elif not quarantine_key in self.quarantined:
            self.quarantined[quarantine_key] = int(time.time()) + _QUARANTINE_EXPIRATION_SEC
            (gap, prefix) = quarantine_key
            self.add_slice(prefix, gap)

    def cpu_port_sniffer(self):
        self.routing_table = {} # prefix -> AS
        self.quarantined = {} # (AS, prefix) -> quarantine expire time
        self.blocked_as = []
        self.allowed = [] # (AS, prefix)
        psock = psocket.SocketHndl(timeout=999999, iface_name=_CPU_PORT_VETH)
        while self.running:
            for raw in psock:
                self.cpu_port_handler(raw, psock)

if __name__ == "__main__":
    ctrl = Controller()

    cleanup_thread = threading.Thread(target=ctrl.do_expired_rule_cleanup)
    cleanup_thread.start()

    cpu_port_thread = threading.Thread(target=ctrl.cpu_port_sniffer)
    cpu_port_thread.start()
    try:
        ctrl.await_notifications()
    except:
        ctrl.running = False
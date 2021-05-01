import nnpy
import struct
import termcolor as T
import operator
import time
import threading

from numpy import std, mean
from sswitch_API import SimpleSwitchAPI

_THRIFT_PORT = 22222
_SIGNAL_THRESHOLD = 10
_RULE_EXPIRATION_SEC = 900
_DO_LOG = True

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
        ports = self.controller.client.bm_dev_mgr_show_ports()
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
        prefix_int = int(prefix[0])
        prefix_str = "{}.0.0.0/8".format(prefix_int)
        log("sending slice for LPM {}...".format(prefix_str), "red")
        rule_handle = self.controller.table_add("respondBgp", "slice", [prefix_str], [str(n)]) # slice in bits 
        self.slice_rules[prefix_int] = {'handle': rule_handle, 'expiration': int(time.time()) + _RULE_EXPIRATION_SEC} 

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
                if not int(prefix[0]) in self.slice_rules:
                    self.add_slice(prefix, gap)
                else:
                    log("slice rule for this prefix already exists.")
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

if __name__ == "__main__":
    ctrl = Controller()
    cleanup_thread = threading.Thread(target=ctrl.do_expired_rule_cleanup)
    cleanup_thread.start()
    try:
        ctrl.await_notifications()
    except:
        ctrl.running = False
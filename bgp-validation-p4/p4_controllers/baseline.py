import nnpy
import struct
import termcolor as T
import operator
import time
import threading

from numpy import std, mean
from sswitch_API import SimpleSwitchAPI

_THRIFT_PORT = 22223
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
        return digest

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
    try:
        ctrl.await_notifications()
    except:
        ctrl.running = False
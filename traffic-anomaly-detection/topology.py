#!/usr/bin/env python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from p4_mininet import P4Switch

import sys
import signal
import threading
import time

setLogLevel('info')
ATTACK_NODES_N = 1
nodes = []

class SimpleTopo(Topo):
    def __init__(self):
        super(SimpleTopo, self).__init__()

        _THRIFT_PORT = 22222
        router = self.addSwitch('R1', sw_path='/usr/bin/simple_switch',
            json_path='p4src/detect.json', thrift_port=_THRIFT_PORT, log_console=False)

        host = self.addNode('H1', ip='10.0.0.1/8')
        self.addLink(router, host, bw=100)

        for i in range(ATTACK_NODES_N):
            ip = '10.0.0.{}/8'.format(i + 2)
            nodes.append(self.addNode('HA{}'.format(i), ip=ip))
            self.addLink(nodes[-1], router, bw=100)

def main():
    net = Mininet(
        topo=SimpleTopo(), 
        switch=P4Switch, 
        controller = None,
        autoSetMacs = True
    )

    net.start()

    # For toy example, bucket size = 2 sec, window = 10 sec.
    #CLI(net)

    print('Ready. Start controller within the next 5 seconds.')
    time.sleep(5)

    print('Starting test over 75s.')
    # Start attack script on nodes, which do the traffic procedures.
    # Only display stdout from the first instance.
    for i in range(ATTACK_NODES_N):
        if i == 0:
            net.getNodeByName('HA{}'.format(i)).popen('python test.py', stdout=sys.stdout)
        else:
            net.getNodeByName('HA{}'.format(i)).popen('python test.py')
    
    time.sleep(75)

    net.stop()


if __name__ == "__main__":
    main()

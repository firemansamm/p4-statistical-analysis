#!/usr/bin/env python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from p4_mininet import P4Switch

import sys
import signal

setLogLevel('info')

class SimpleTopo(Topo):
    def __init__(self):
        super(SimpleTopo, self).__init__()

        _THRIFT_PORT = 22222
        router = self.addSwitch('R1', sw_path='/usr/bin/simple_switch',
            json_path='p4src/bench.json', thrift_port=_THRIFT_PORT, log_console=False)

        host = self.addNode('H1')
        self.addLink(router, host)

def main():

    net = Mininet(
        topo=SimpleTopo(), 
        switch=P4Switch, 
        controller = None,
        autoSetMacs = True
    )

    net.start()
    output = open('bench.log', 'w')
    popen = net.getNodeByName('H1').popen('python test.py', stdout=output, stderr=sys.stderr)
    try:
        popen.wait()
    except KeyboardInterrupt:
        popen.send_signal(signal.SIGTERM)
        raise

    #CLI(net)
    net.stop()


if __name__ == "__main__":
    main()

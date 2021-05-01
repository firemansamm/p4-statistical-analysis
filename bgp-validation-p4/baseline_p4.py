#!/usr/bin/env python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg, info, setLogLevel
from mininet.util import dumpNodeConnections, quietRun, moveIntf
from mininet.cli import CLI
from mininet.node import Switch, OVSKernelSwitch, Controller, RemoteController
from mininet.link import TCLink

from p4_mininet import P4Switch, P4Host

from subprocess import Popen, PIPE, check_output
from time import sleep, time
from multiprocessing import Process
from argparse import ArgumentParser

import sys
import os
import termcolor as T
import time

setLogLevel('info')

parser = ArgumentParser("Configure simple BGP network in Mininet.")
parser.add_argument('--rogue', action="store_true", default=False)
parser.add_argument('--sleep', default=3, type=int)
args = parser.parse_args()

FLAGS_rogue_as = args.rogue
ROGUE_AS_NAME = 'R6'

def log(s, col="green"):
    print(T.colored(s, col))


class Router(Switch):
    """Defines a new router that is inside a network namespace so that the
    individual routing entries don't collide.

    """
    ID = 0
    def __init__(self, name, **kwargs):
        kwargs['inNamespace'] = True
        Switch.__init__(self, name, **kwargs)
        Router.ID += 1
        self.switch_id = Router.ID

    @staticmethod
    def setup():
        return

    def start(self, controllers):
        print("Controllers:")
        print(controllers)
        pass

    def stop(self):
        self.deleteIntfs()

    def log(self, s, col="magenta"):
        print(T.colored(s, col))


class SimpleTopo(Topo):
    """A1 - Victim
       A3 - Attacker.

    """
    def __init__(self):
        # Add default members to class.
        super(SimpleTopo, self).__init__()
        num_hosts_per_as = 3
        num_ases = 8
        num_hosts = num_hosts_per_as * num_ases
        # The topology has one router per AS
        routers = []
        for i in range(num_ases):
            # if i == 5: # skip rogue AS 6
                # continue
            router = self.addSwitch('R%d' % (i+1)) 
            routers.append(router)
        hosts = []

        #Add OF Switches
        routers.append(self.addSwitch('R83', cls=OVSKernelSwitch))
        routers.append(self.addSwitch('R84', cls=OVSKernelSwitch))
        routers.append(self.addSwitch('R32', cls=OVSKernelSwitch))

        # We replace R12, the bridge to the victim, with a P4 switch instead of an OpenFlow switch.
        # R12 runs monitor.p4, and connects to a controller using thrift port 22222.
        _THRIFT_PORT = 22222
        routers.append(self.addSwitch('R12', cls=P4Switch, sw_path='/usr/bin/simple_switch',
            json_path='p4src/baseline.json', thrift_port=_THRIFT_PORT, log_console=False))

        for i in range(num_ases):
            router = 'R%d' % (i+1)
            for j in range(num_hosts_per_as):
                hostname = 'h%d_%d' % (i+1, j+1)
                host = self.addNode(hostname)
                hosts.append(host)
                self.addLink(router, host)

        bandwitdh_capacity = 10
        self.addLink('R1','R12', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        self.addLink('R12','R2', cls=TCLink, bw = bandwitdh_capacity) #Mbps


        self.addLink('R2', 'R32', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        self.addLink('R32', 'R3', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        
        self.addLink('R3','R5', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        
        self.addLink('R3','R83', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        self.addLink('R83','R8', cls=TCLink, bw = bandwitdh_capacity) #Mbps

        self.addLink('R4','R5', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        self.addLink('R4','R6', cls=TCLink, bw = bandwitdh_capacity) #Mbps

        self.addLink('R4','R84', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        self.addLink('R84','R8', cls=TCLink, bw = bandwitdh_capacity) #Mbps

        # Attacker
        # routers.append(self.addSwitch('R6'))
        # for j in range(num_hosts_per_as):
        #     hostname = 'h%d_%d' % (6, j+1)
        #     host = self.addNode(hostname)
        #     hosts.append(host)
        #     self.addLink('R6', hostname, cls=TCLink, bw = bandwitdh_capacity) #Mbps
        
        self.addLink('R7', 'R5', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        self.addLink('R7', 'R6', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        return


def getIP(hostname):
    AS, idx = hostname.replace('h', '').split('_')
    AS = int(AS)
    if AS == 6:
        AS = 1
    ip = '%s.0.%s.1/24' % (10+AS, idx)
    return ip


def getGateway(hostname):
    AS, idx = hostname.replace('h', '').split('_')
    AS = int(AS)
    # This condition gives AS7 the same IP range as AS1 so it can be an
    # attacker.
    if AS == 6:
        AS = 1
    gw = '%s.0.%s.254' % (10+AS, idx)
    return gw


def startWebserver(net, hostname, text="Default web server"):
    host = net.getNodeByName(hostname)
    return host.popen("python webserver.py --text '%s'" % text, shell=True)

def startImageWebserver(net, hostname, img_path="legit-duck.jpg"):
    host = net.getNodeByName(hostname)
    return host.popen("python image-webserver.py --img_path '%s'" % img_path, shell=True)


def main():
    os.system("rm -f /tmp/R*.log /tmp/R*.pid /tmp/bm*.ipc /tmp/bm*.log logs/*")
    os.system("mn -c >/dev/null 2>&1")
    os.system("killall -9 zebra bgpd > /dev/null 2>&1")
    os.system('pgrep -f image-webserver.py | xargs kill -9')
    os.system('pgrep -f webserver.py | xargs kill -9')

    net = Mininet(
        topo=SimpleTopo(), 
        switch=Router, 
        controller = None,
        autoSetMacs = True
    )

    # Start the old OF controllers.
    os.system("ryu-manager --ofp-tcp-listen-port 6633 ryu_controllers/R3_controller.py > controller_logs/R3_controller_logs.log 2>&1 &")
    net.addController('c0', controller = RemoteController, ip='127.0.0.1', port=6633)

    net.start()

    # Start the P4 controller.
    # os.system("cd p4_controllers; python R1_monitor.py > ../controller_logs/R1_monitor_logs.log 2>&1 &")
    

    # Set bridge protocols to OF13 for R83 and R84
    os.system("sudo ovs-vsctl set bridge R83 protocols=OpenFlow13")
    os.system("sudo ovs-vsctl set-controller R83 tcp:127.0.0.1:6633")

    os.system("sudo ovs-vsctl set bridge R84 protocols=OpenFlow13")
    os.system("sudo ovs-vsctl set-controller R84 tcp:127.0.0.1:6633")

    os.system("sudo ovs-vsctl set bridge R32 protocols=OpenFlow13")
    os.system("sudo ovs-vsctl set-controller R32 tcp:127.0.0.1:6633")

    for router in net.switches:
        router.cmd("sysctl -w net.ipv4.ip_forward=1")
        router.waitOutput()
        if router.name == 'R8':
            router.cmd('tcpdump -i R8-eth4 -w R8dump_eth4.pcap&')

    log("Waiting %d seconds for sysctl changes to take effect..."
        % args.sleep)
    sleep(args.sleep)

    rogue_router = None
    for router in net.switches:
        #Skip Rogue
        if router.name == ROGUE_AS_NAME and not FLAGS_rogue_as:
            rogue_router = router
            continue
        if router.name == 'R83' or router.name == 'R84' or router.name == 'R12' or router.name == 'R32':
            continue
        router.cmd("zebra -f conf/zebra-%s.conf -d -i /tmp/zebra-%s.pid -z /tmp/zebra-%s.sock > logs/%s-zebra-stdout 2>&1" % (router.name, router.name, router.name, router.name))
        router.waitOutput()
        router.cmd("bgpd -f conf/bgpd-%s.conf -d -i /tmp/bgp-%s.pid -z /tmp/zebra-%s.sock > logs/%s-bgpd-stdout 2>&1" % (router.name, router.name, router.name, router.name), shell=True)
        router.waitOutput()
        log("Starting zebra and bgpd on %s" % router.name)

    for host in net.hosts:
        host.cmd("ifconfig %s-eth0 %s" % (host.name, getIP(host.name)))
        host.cmd("route add default gw %s" % (getGateway(host.name)))

    log("Starting web servers", 'yellow')
    image_path = "legit-duck-big.jpg"
    startImageWebserver(net, 'h8_1', img_path=image_path)
    startImageWebserver(net, 'h8_2', img_path=image_path)
    startImageWebserver(net, 'h8_3', img_path=image_path)

    startImageWebserver(net, 'h1_1', img_path=image_path)
    startImageWebserver(net, 'h1_2', img_path=image_path)
    startImageWebserver(net, 'h1_3', img_path=image_path)

    startWebserver(net, 'h1_1', "Default web server")
    startWebserver(net, 'h7_1', "*** Attacker web server ***")

    #log("sleeping 10s before launching attack...", "red")
    #sleep(10)
    #ogue_router.cmd("zebra -f conf/zebra-%s.conf -d -i /tmp/zebra-%s.pid -z /tmp/zebra-%s.sock > logs/%s-zebra-stdout 2>&1" % (ROGUE_AS_NAME, ROGUE_AS_NAME, ROGUE_AS_NAME, ROGUE_AS_NAME))
    #rogue_router.waitOutput()
    #rogue_router.cmd("bgpd -f conf/bgpd-%s.conf -d -i /tmp/bgp-%s.pid -z /tmp/zebra-%s.sock > logs/%s-bgpd-stdout 2>&1" % (ROGUE_AS_NAME, ROGUE_AS_NAME, ROGUE_AS_NAME, ROGUE_AS_NAME), shell=True)
    #rogue_router.waitOutput()

    # Launch victim requests to sentinel. This script requests an image from
    # from the sentinel at every 2 seconds. This guarantees that there is an
    # outgoing TCP flow with payload from the sentinel to the victim.
    # victom_host = net.getNodeByName("h1_1")
    # victom_host.popen("./website-request-duck-from-h8-1.sh")

    show_bridges_script = "show_bridges.sh"
    CLI(net, script=show_bridges_script)
    CLI(net)
    net.stop()
    os.system("kill $(ps aux | grep /topology/website-AS | awk '{print $2}')") 
    # os.system("kill $(ps aux | grep @website-flow | awk '{print $2}')")
    # os.system("kill $(ps aux | grep @curl-format | awk '{print $2}')")

    os.system("killall -9 zebra bgpd ryu-manager")
    os.system('pgrep -f image-webserver.py | xargs kill -9')
    os.system('pgrep -f webserver.py | xargs kill -9')


if __name__ == "__main__":
    main()

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

_SENTINEL_CPU_PORT_VETH = ['veth250', 'veth251']
_MONITOR_THRIFT_PORT = 22222
_SENTINEL_THRIFT_PORT = 22223

USE_P4_MONITOR = False
USE_P4_SENTINEL = True

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

        if USE_P4_MONITOR:
            routers.append(self.addSwitch('R12', cls=P4Switch, sw_path='/usr/bin/simple_switch',
                json_path='p4src/monitor.json', thrift_port=_MONITOR_THRIFT_PORT, log_console=False))
        else:
            routers.append(self.addSwitch('R12', cls=P4Switch, sw_path='/usr/bin/simple_switch',
                json_path='p4src/baseline.json', thrift_port=_MONITOR_THRIFT_PORT, log_console=False))

        # We need to attach all the links going towards R8 to a switch R88 running P4, since 
        # quagga cannot run on the P4 switch.

        # Previously: [R84, R83] <-> R8
        # Now: [R84, R83] <-> R88 <-> R8

        if USE_P4_SENTINEL:
            routers.append(self.addSwitch('R88', cls=P4Switch, sw_path='/usr/bin/simple_switch',
                json_path='p4src/sentinel.json', thrift_port=_SENTINEL_THRIFT_PORT, log_console=False, cpu_port=_SENTINEL_CPU_PORT_VETH[0]))
        else:
            routers.append(self.addSwitch('R88', cls=P4Switch, sw_path='/usr/bin/simple_switch',
                json_path='p4src/baseline.json', thrift_port=_SENTINEL_THRIFT_PORT, log_console=False))

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
        self.addLink('R83','R88', cls=TCLink, bw = bandwitdh_capacity) #Mbps

        self.addLink('R4','R5', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        self.addLink('R4','R6', cls=TCLink, bw = bandwitdh_capacity) #Mbps

        self.addLink('R4','R84', cls=TCLink, bw = bandwitdh_capacity) #Mbps
        self.addLink('R84','R88', cls=TCLink, bw = bandwitdh_capacity) #Mbps

        self.addLink('R88', 'R8', cls=TCLink, bw = bandwitdh_capacity)
        self.addLink('R88', 'R8', cls=TCLink, bw = bandwitdh_capacity)
        
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
    os.system("rm -f *.pcap")

    # Create a veth pair to use as our CPU port. Our sentinel controller will be bound on the other end.
    # The sentinel daemon must receive using scapy, because there will be no IP stack on this link.
    os.system('ip link add {} type veth peer name {}'.format(_SENTINEL_CPU_PORT_VETH[0], _SENTINEL_CPU_PORT_VETH[1]))
    for veth in _SENTINEL_CPU_PORT_VETH:
        os.system("ip link set {} up".format(veth))
        os.system("ip link set {} promisc on".format(veth))

    net = Mininet(
        topo=SimpleTopo(), 
        switch=Router, 
        controller = None,
        autoSetMacs = True
    )

    # Start the old OF controllers.
    os.system("ryu-manager --ofp-tcp-listen-port 6635 ryu_controllers/R3_controller.py > controller_logs/R3_controller_logs.log 2>&1 &")
    # os.system("ryu-manager --observe-links ryu_controllers/bgp_R8_sentinel_shift_tcp_flow.py > controller_logs/R8_controller_logs.log 2>&1 &")

    log("waiting for the controllers to start up...")
    sleep(2)

    net.addController('c2', controller = RemoteController, ip='127.0.0.1', port=6635)

    net.start()

    # Start the P4 controller.
    #if USE_P4_MONITOR:
    #    os.system("cd p4_controllers; python R1_monitor.py > ../controller_logs/R1_monitor_logs.log 2>&1 &")     

    # Set bridge protocols to OF13 for R83 and R84
    os.system("sudo ovs-vsctl set bridge R83 protocols=OpenFlow13")
    os.system("sudo ovs-vsctl set-controller R83 tcp:127.0.0.1:6635")

    os.system("sudo ovs-vsctl set bridge R84 protocols=OpenFlow13")
    os.system("sudo ovs-vsctl set-controller R84 tcp:127.0.0.1:6635")

    os.system("sudo ovs-vsctl set bridge R32 protocols=OpenFlow13")
    os.system("sudo ovs-vsctl set-controller R32 tcp:127.0.0.1:6635")

    #if not USE_P4_MONITOR:
    #    os.system("sudo ovs-vsctl set bridge R12 protocols=OpenFlow13")
    #    os.system("sudo ovs-vsctl set-controller R12 tcp:127.0.0.1:6635")

    #if not USE_P4_SENTINEL:
    #    os.system("sudo ovs-vsctl set bridge R88 protocols=OpenFlow13")
    #    os.system("sudo ovs-vsctl set-controller R88 tcp:127.0.0.1:6633")

    for router in net.switches:
        router.cmd("sysctl -w net.ipv4.ip_forward=1")
        router.waitOutput()
        #if router.name == 'R1':
        #    router.cmd('tcpdump -i R1-eth4 -w R1dump_eth4.pcap&')
        #if router.name == 'R8':
        #    router.cmd('tcpdump -i R8-eth4 -w R8dump_eth4.pcap&')
        #if router.name == 'R3':
        #    router.cmd('tcpdump -i R4-eth1 -w R3dump_eth1.pcap&')
        #
        #if router.name == 'R88':
        #    router.cmd('tcpdump -i R88-eth1 -w R88dump_eth1.pcap&')
        #    router.cmd('tcpdump -i R88-eth3 -w R88dump_eth3.pcap&')
        #if router.name == 'R83':
        #    router.cmd('tcpdump -i R83-eth1 -w R83dump_eth1.pcap&')
        #    router.cmd('tcpdump -i R83-eth2 -w R83dump_eth2.pcap&')
        #    
        #if router.name == 'R2':
        #    router.cmd('tcpdump -i R2-eth2 -w R2dump_eth2.pcap&')

    #
    # veths don't like MTU values by default because of TSO - it expects
    # the interface to be able to fragment packets for MTU, but the veth doesn't
    # even try.
    # But if we try and send a packet greater than MTU using pcap_sendpacket
    # (internal to bmv2), it throws an error and the packet is lost.
    # 
    # Interestingly enough, something similar happens to checksums: they are wrong
    # and the other end drops the packets without ever processing them, but we fix checksums
    # in our P4 switch, so we never run into a problem with them.
    #
    # If we turn off TSO, the kernel does the segmentation for us, 
    # and MTU is respected.
    #
    net.getNodeByName('h8_1').cmd("ethtool -K h8_1-eth0 tso off gso off ufo off")
    net.getNodeByName('h1_1').cmd("ethtool -K h8_1-eth0 tso off gso off ufo off")
    

    log("Waiting %d seconds for sysctl changes to take effect..."
        % args.sleep)
    sleep(args.sleep)

    rogue_router = None
    for router in net.switches:
        #Skip Rogue
        if router.name == ROGUE_AS_NAME:
            rogue_router = router
            continue
        if router.name == 'R83' or router.name == 'R84' or router.name == 'R12' or router.name == 'R32' or router.name == 'R88':
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
    #rogue_router.cmd("zebra -f conf/zebra-%s.conf -d -i /tmp/zebra-%s.pid -z /tmp/zebra-%s.sock > logs/%s-zebra-stdout 2>&1" % (ROGUE_AS_NAME, ROGUE_AS_NAME, ROGUE_AS_NAME, ROGUE_AS_NAME))
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

    # Tear down the CPU port veth.
    for veth in _SENTINEL_CPU_PORT_VETH:
        os.system("ip link set {} down".format(veth))
    
    os.system("ip link delete {}".format(_SENTINEL_CPU_PORT_VETH[0]))

    os.system("kill $(ps aux | grep /topology/website-AS | awk '{print $2}')") 
    # os.system("kill $(ps aux | grep @website-flow | awk '{print $2}')")
    # os.system("kill $(ps aux | grep @curl-format | awk '{print $2}')")

    os.system("killall -9 zebra bgpd ryu-manager")
    os.system('pgrep -f image-webserver.py | xargs kill -9')
    os.system('pgrep -f webserver.py | xargs kill -9')
    os.system("tar -czvf pcap.tgz *.pcap")


if __name__ == "__main__":
    main()

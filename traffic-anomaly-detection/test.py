from scapy.layers.inet import IP, Ether
from pypacker import psocket
from time import sleep
from random import uniform
import os

os.system("ethtool -K HA0-eth0 tx off")

TARGET_DEST = '10.0.0.1'
DEBUG = True
def log(s):
    if DEBUG:
        print(s)

send_sock = psocket.SocketHndl(timeout=999999, iface_name='HA0-eth0')

def send_packet():
    pkt = Ether()/IP(dst=TARGET_DEST, ttl=64, proto=6)
    send_sock.send(bytes(pkt))    


def send_some_packets(rate, duration):
    n = rate * duration
    for i in range(n):
        send_packet()
        # Introduce some variance - otherwise the standard deviation is super small.
        sleep(uniform(0.8, 1.2) / rate)

def ramp(start, end, duration):
    # Raise speed every second.
    log('Ramping from {} to {} over {}s. No alert should be raised.'.format(start, end, duration))
    step = (end - start) / duration
    for i in range(duration):
        send_some_packets(int(start + (i * step)), 1)

# Establish baseline traffic for 10s. 
# Low traffic (10 packets a second).
log('Establishing baseline of 10 packets a second for 10 seconds.')
send_some_packets(10, 10)

# Step up: suddenly jump to 50 packets a second for 10s.
# Should raise an alert.
log('Raising traffic to 50 per second for 10 seconds. Expect an alert on the controller.')
send_some_packets(50, 10)


# Step down: suddenly jump back to 10 packets a second for 10s.
# Should raise an alert.
log('Dropping traffic to 10 per second for 10 seconds. Expect an alert on the controller.')
send_some_packets(10, 10)

# Ramp up: raise to 50 packets a second over 10 seconds.
# Shouldn't raise an alert.
ramp(10, 50, 20)

# Ramp down: drop to 10 packets a second over 10 seconds.
# Shouldn't raise an alert.
ramp(50, 10, 20)
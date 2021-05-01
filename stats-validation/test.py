import sys
import time
import random
import struct
import math
import numpy as np
import threading
from progressbar import *
from functools import reduce
from scapy.layers.inet import *
from scapy.packet import Raw
from pypacker import psocket
from scapy.all import get_if_list, get_if_hwaddr, sendp

# There is a small problem. Even if we can signal the switch
# to try and flush its existing stat counters, we can't zero
# the register. This means (at least during testing) that if
# we want to clear the registers, we must reset Mininet.

TARGET_IFACE = conf.iface #'H1-eth0'
DELAY_MSEC = 7.5
ERROR_THRESHOLD = 1

RANGE_ABS_MAX = 255
NODELAY_TEST = True

ifaces = get_if_list()

if TARGET_IFACE not in ifaces:
    print('Could not find interface {}. Check TARGET_IFACE exists on the host.'.format(TARGET_IFACE))
#conf.iface = TARGET_IFACE
local_mac = get_if_hwaddr(TARGET_IFACE)

send_sock = psocket.SocketHndl(timeout=999999, iface_name = TARGET_IFACE)

run = True
values = []
freq = {}
cache = []

def compute_var(nx):
    return np.var(nx)

def compute_std(nx):
    return np.std(nx)

def compute_values():
    n = len(freq.keys())
    vals = list(freq.values())
    xsum = reduce((lambda x, y: x + y), vals)
    xsum_sq = reduce((lambda x, y: x + y), list(map((lambda x: (x**2)), vals)))
    nx = list(map((lambda x: (n * x)), vals))
    varnx = compute_var(nx)
    stdnx = compute_std(nx)
    stdn = np.std(vals)
    return (n, xsum, xsum_sq, varnx, round(stdnx, 3), round(stdn, 3))

max_err = 0
mean_err = 0
nn = 0

# Analyze https://www.caida.org/data/passive/passive_dataset_download.xml
# to see what sort of distribution we can look at.
rand = np.random.normal(0.0, 15.0)

# This represents the total amount of unique values we may encounter. This is already
# way above spec when it comes to out of order packets if we're talking about the
# simulated environment for this project, since:
# (1) if a packet is 511 segments out of order, something has gone horribly wrong
# (2) there are probably not 511 different sizes of segments, due to MTU on networks?
#
# Additionally, due to the constraints in the implemented algorithm (re: BGP), the 
# threshold at which we start actively looking for a signal is sufficiently low (5!).

def send_rand():
    r = random.randint(-RANGE_ABS_MAX, RANGE_ABS_MAX)
    values.append(r)
    if r not in freq:
        freq[r] = 1
    else:
        freq[r] = freq[r] + 1

    # Cache the values. Sometimes the switch is faster than us, so if we cache it
    # we can check if the value was right at the time.
    #
    # This arises from a race condition, where the switch has processed stats_push_freq
    # of the next packet before stats_get_data from the current packet has returned.
    # eg. Say two packets for the exact Xsum=21 value arrive, since by the time the response
    # is put together for the packet that set Xsum=20, another packet has arrived and set Xsum=21.
    # The stats are pulled, and the data reflects Xsum=21. The register states are generally consistent though.
    #
    # This **should be** of little consequence if we're actually working with the data on the switch itself,
    # since we generally hope to have the latest state of the stat counter due to the volume of the flows
    # and we shouldn't depend on a single value (esp. during high traffic).
    cache.append(compute_values())
    pkt = Ether(type=0x88b5, dst='12:34:56:78:9a:bc')
    pkt.add_payload(r.to_bytes(4, 'big', signed=True))
    #sendp(pkt, verbose=False)
    send_sock.send(bytes(pkt))

err_encountered = 0
errs = []

def sniffer():
    psock = psocket.SocketHndl(timeout=999999, iface_name = TARGET_IFACE)
    for pkt in psock:
        eth = Ether(pkt)
        if eth.type == 0x88b5 and eth.dst == local_mac:
            process_pkt(eth)


def process_pkt(pkt):
    global err_encountered
    global max_err
    global mean_err
    global run
    global nn

    print('[*] Incoming packet: {0}'.format(pkt.summary()))
    raw = pkt.getlayer(Raw)
    n, xsum, xsum_sq, varnx, stdnx = struct.unpack(">IIIII", bytes(raw))
    print("Switch   >> n = {0}, xsum = {1}, xsum_sq = {2}, varnx = {3:<10}, stdnx = {4:<10} (std(x)={5})".format(
        n, xsum, xsum_sq, varnx, stdnx, round(stdnx / n, 3)))
    tup = cache[xsum - 1]
    
    if stdnx > 0:
        err = (abs(stdnx - tup[4]) / stdnx) * 100
    else:
        err = 0
    if not math.isnan(err):
        max_err = max(err, max_err)
        mean_err = ((mean_err * nn) + err) / (nn + 1)
    nn = nn + 1

    print("Computed >> n = {0}, xsum = {1}, xsum_sq = {2}, varnx = {3:<10}, stdnx = {4:<10} (std(x)={5}/{6}) (error={7}%, max={8}%, mean={9}%)".format(
        *tup, round(tup[4] / tup[0], 3), round(err, 3), round(max_err, 3), round(mean_err, 3)))

    errs.append(err)
    err_check = abs(stdnx - tup[4]) > math.ceil(0.15 * tup[4])
    # > 15% error rounded up (important for low values where 15% < 1) or var is wrong
    # Since Var(NX) is an integer calculation, it must be exact.
    #
    # In the no delay test, we want to see if the values eventually coalesce to the correct values.
    # We ignore errors, and manually verify the final output. If they match, the intermediate
    # race condition values are probably valid (but in different order to the input).

    if err_check or int(varnx) != tup[3]:
        print("Error check failed! Error: {}, Var: {}".format(err_check, int(varnx) != tup[3]))
        err_encountered = err_encountered + 1

        # If there are more than X consecutive errors, something is probably wrong.
        # We keep this at 1 with delay to prove the computation works.
        if err_encountered >= ERROR_THRESHOLD:
            run = False
            raise Exception("stop")
    else:
        err_encountered = 0
    
    if nn == 10000:
        raise Exception("stop")


sniff_thread = threading.Thread(target=sniffer)
sniff_thread.start()

PACKETS_TO_SEND = 10000

# Send packets with some delay. Error if there are more than ERROR_THRESHOLD consecutive errors.
# No delay would be a better simulation, but it seems that there are race conditions that need
# to be worked out (or not, if they don't actually affect the soundness of the data).
widgets = [
    RotatingMarker(),
    Percentage(),
    ' ', SimpleProgress(format='(%s)' % SimpleProgress.DEFAULT_FORMAT,),
    ' ', Bar(marker='=', left='[', right=']'),
    ' ', Timer(),
    ' ', AdaptiveETA()
]
for i in progressbar(range(PACKETS_TO_SEND), marker='=', widgets=widgets):
    if not run:
        print('\nEncountered an error. Check log file for details. Exiting.', file=sys.stderr)
        break
    send_rand()
    if not NODELAY_TEST:
        time.sleep(0.001 * DELAY_MSEC)

print(errs)

if run:
    print('\nTest completed successfully. Exiting.', file=sys.stderr)
sys.exit(0)
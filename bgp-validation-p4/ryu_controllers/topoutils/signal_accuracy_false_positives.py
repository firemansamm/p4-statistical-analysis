from __future__ import division


import json
from topology_utils import Signal_Detector
import random
from pprint import pprint

detector = Signal_Detector(10)
trials = 100000
counter = 0

false_pos_dict = {}
for i in range (1, 301, 1):
    false_pos_dict[i] = 0


for j in range(trials):
    freqdict = {5792: random.randint(0,1), 
                -5792: random.randint(0,1), 
                7420: random.randint(0,1), 
                -4344: random.randint(0,1),
                -2896: random.randint(0,1),
                2896: random.randint(0,1),
                1448: random.randint(0,1),
                -23168: random.randint(0,1), 
                4344: random.randint(0,1), 
                23168: random.randint(0,1), 
                20272: random.randint(0,1),
                12: random.randint(0,1),
                13: random.randint(0,1),
                14: random.randint(0,1),
                15: random.randint(0,1),
                16: random.randint(0,1),
                17: random.randint(0,1),
                18: random.randint(0,1),
                19: random.randint(0,1),
                # 20: random.randint(0,1),
                # 21: random.randint(0,1),
                # 22: random.randint(0,1),
                # 23: random.randint(0,1),
                # 24: random.randint(0,1),
                # 25: random.randint(0,1),
                # 26: random.randint(0,1),
                # 27: random.randint(0,1),
                # 28: random.randint(0,1),
                # 29: random.randint(0,1),
                30: random.randint(0,1)}
    freqdict = {k: v for k, v in freqdict.items() if v is not 0}
    for i in range(1, 301, 1):
        packet_ooo = random.choice(list(freqdict.keys()))
        freqdict[packet_ooo] += 1
        if detector.has_received_signal(freqdict):
            counter += 1
            false_pos_dict[i] += 1
            print("%d/%d"%(j,trials))
            break
for i in range(1, 301, 1):
    false_pos_dict[i] = false_pos_dict[i]/trials * 100
pprint(false_pos_dict)
with open('chance-false-positive-per-packet.json', 'w') as fp:
    json.dump(false_pos_dict, fp)
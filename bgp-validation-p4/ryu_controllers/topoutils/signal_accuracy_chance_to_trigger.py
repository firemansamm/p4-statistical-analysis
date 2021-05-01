from __future__ import division


import json
from topology_utils import Signal_Detector
import random

detector = Signal_Detector(10)
trials = 10000

percentages = []

for top_limit in range(1,101,1):
    counter = 0
    for i in range(trials):
        freqdict = {5792: random.randint(1,top_limit), 
                    -5792: random.randint(1,top_limit), 
                    7420: random.randint(1,top_limit), 
                    -4344: random.randint(1,top_limit),
                    -2896: random.randint(1,top_limit),
                    2896: random.randint(1,top_limit),
                    1448: random.randint(1,top_limit),
                    -23168: random.randint(1,top_limit), 
                    4344: random.randint(1,top_limit), 
                    23168: random.randint(1,top_limit), 
                    20272: random.randint(1,top_limit),
                    12: random.randint(1,top_limit),
                    13: random.randint(1,top_limit),
                    14: random.randint(1,top_limit),
                    15: random.randint(1,top_limit),
                    16: random.randint(1,top_limit),
                    17: random.randint(1,top_limit),
                    18: random.randint(1,top_limit),
                    19: random.randint(1,top_limit),
                    20: random.randint(1,top_limit),
                    21: random.randint(1,top_limit),
                    22: random.randint(1,top_limit),
                    23: random.randint(1,top_limit),
                    24: random.randint(1,top_limit),
                    25: random.randint(1,top_limit),
                    26: random.randint(1,top_limit),
                    27: random.randint(1,top_limit),
                    28: random.randint(1,top_limit),
                    29: random.randint(1,top_limit),
                    30: random.randint(1,top_limit)}
        if detector.has_received_signal(freqdict):
            counter += 1
        else:
            pass
    print("Top Limit #%d"%(top_limit))
    print("False Positive chance: {0:.4%}".format(counter/trials))
    percentages.append(counter/trials*100)
with open('percentages.json', 'w') as fp:
    json.dump(percentages, fp)
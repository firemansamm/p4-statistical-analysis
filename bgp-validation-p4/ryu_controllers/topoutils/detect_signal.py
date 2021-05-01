import numpy as np
from numpy import std, mean
import matplotlib.pyplot as plt
anomalies = []

freq_dict = {
    7: 5
}

class Signal_Detector:

    def __init__(self, SIGNAL_THRESHOLD):
        self.SIGNAL_THRESHOLD = SIGNAL_THRESHOLD

    def has_received_signal(self, freq_dict):
        data = []
        for key, value in freq_dict.items():
            data.append(value)
        if len(data) == 0:
            return False
        if max(data) < self.SIGNAL_THRESHOLD:
            return False
        return True


    # Function to Detection Outlier on one-dimentional datasets.
    # Returns the encoded shift amount in the flow 
    def get_outlier(self, freq_dict):

        amount = 0

        if len(freq_dict) == 1:
            amount = list(freq_dict.keys())[0]
            return amount
        
        if len(freq_dict) == 2:
            max_freq = 0
            max_amount = 0
            for key, value in freq_dict.items():
                if value > max_freq:
                    max_freq = value
                    max_amount = key
            return max_amount
        
        # Set upper and lower limit to 3 standard deviation
        data = []
        for key, value in freq_dict.items():
            data.append(value)
        
        data_std = std(data)
        data_mean = mean(data)
        anomaly_cut_off = data_std * 1
        
        lower_limit  = data_mean - anomaly_cut_off 
        upper_limit = data_mean + anomaly_cut_off

        # Generate outliers
        for key, value in freq_dict.items():
            if value > upper_limit or value < lower_limit:
                return key

my_detector = Signal_Detector(5)

if my_detector.has_received_signal(freq_dict):
    print(my_detector.get_outlier(freq_dict))
else:
    print("No signal received...")
import sys
import json
import requests
from datetime import datetime
from configparser import ConfigParser
import os

class DataCorrelator():
    def __init__(self,time_window):
        self.time_window = time_window

    def correlate_via_time(self):
        print("Time")
    
    def correlate_via_src_ip(self):
        print("SRC IP")
    
    def correlate_via_dest_ip(self):
        print("DEST IP")
    
    def correlate_via_dest_port(self):
        print("DEST PORT")
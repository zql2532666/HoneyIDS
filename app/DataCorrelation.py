import sys
import json
import requests
from datetime import datetime
from configparser import ConfigParser
import os

class DataCorrelator():
    def __init__(self,time_window):
        self.time_window = time_window

    def correlate_via_time(self,time_window):
        """
            +   Time Window can be specified by the user
            +   Pull the logs within this time window and process them
        """
        print("Time")
    
    def check_one_attacker_attacking_multiple_honeypots():
        """
            Same src ip address + Different dest ip address
        """
    
    def check_one_attacker_attacking_same_dest_port(self):
        """
            Same src ip address + same dest port
        """
        print("DEST PORT")
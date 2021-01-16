import sys
import json
import requests
from datetime import datetime
from configparser import ConfigParser
import os

"""
dataset = [
    {
        date: "",
        source_ip: "",
        destination_ip: "",
        source_port: "",
        destination_port: "",
        token: "",
        honeynode_name: "",
        log_src: "",
        orginal_log: ""
    }
]

Attack Types:
    1.  One Attacker Attacking Multiple Honeypots
    2.  One Attacker Attacking One Honeypot
    3.  Multiple Attackers Attacking One Honeypot
"""
class DataCorrelator():
    def __init__(self,time_threshold):
        self.time_threshold = time_threshold
        """
            +   Time Window can be specified by the user
            +   Pull the logs within this time window and process them
        """
    # def correlate_via_time(self,time_window,data):

    def get_dataset(self,general_logs,nids_logs):
        dataset = []
        for log in general_logs:
            data = {
                "date": log["capture_date"],
                "source_ip": log["source_ip"],
                "destination_ip": log["destination_ip"],
                "source_port": log["source_port"],
                "destination_port": log["destination_port"],
                "token": log["token"],
                "honeynode_name": log["honeynode_name"],
                "log_type": "general",
                "original_log": log
            }
            dataset.append(data)
        
        for log in nids_logs:
            data = {
                "date": log["date"],
                "source_ip": log["source_ip"],
                "destination_ip": log["destination_ip"],
                "source_port": log["source_port"],
                "destination_port": log["destination_port"],
                "token": log["token"],
                "honeynode_name": log["honeynode_name"],
                "log_type": "general",
                "original_log": log
            }
            dataset.append(data)   

        return dataset

    def check_one_attacker_attacking_multiple_honeypots(self,dataset):
        """
            +   Same src ip address + Different dest ip address
            +   src ip == attacker
            +   dest ip == honeypot
        """
        """
            return_data  = {
                "src_ip_1" : [
                    [dest_ip_1,dest_ip_2],
                    [log_1,log_2,log_3]
                    ],
            }

            for key in return_data.keys():
                print(f"source ip: {key}")
                print(f"destination ip list: {return_data.key[0]}")

        """
        return_data = dict()
        for log in dataset:
            source_ip = log["source_ip"]
            destination_ip = log["destination_ip"]
            # https://stackoverflow.com/questions/1602934/check-if-a-given-key-already-exists-in-a-dictionary
            # for some ds reason, I do not need to call .keys() method
            # check if the source_ip is one the keys in return_data
            if source_ip in return_data:
                # return_data["10.1.1.2"]
                # print("source ip found")
                # check if if the current destination ip is already inside the destination_ip_list 
                if destination_ip in return_data[source_ip][0]:  
                    # the destinationn ip is not  added  to the list if it is found inside the destination_ip_list
                    print(f"Same Destination IP address found in the list: {destination_ip}") 
                else:
                    print(f"Adding new dest ip to the list: {destination_ip}")
                    # add the destination ip to the list if it is NOT found inside destination_ip_list
                    return_data[source_ip][0].append(destination_ip)
                    print(f"new dest ip list: {return_data[source_ip][0]}")
                # append the log to the log list 
                return_data[source_ip][1].append(log)
            else:
                # create a new key in return_data with the source ip return_data["10.1.1.1"] = {}
                return_data[source_ip] = list()
                # append the destnation ip as part of a newly declared list return_date["10.1.1.1"] = [192.168.1.1]  
                destination_ip_list = list()
                destination_ip_list.append(destination_ip)
                return_data[source_ip].append(destination_ip_list)
                # append the log as part of a newly declared list return_date["10.1.1.1"] = [[192.168.1.1],[log]]
                log_list = list()
                log_list.append(log)
                return_data[source_ip].append(log_list)

        return return_data
                    
    def check_attacker_attacking_same_honeypot_multiple_times(self,dataset):
        """ 
            +   Same SRC IP + Same dest ip 

            return_data  = {
                (source_ip,destination_ip): [log],
                (source_ip,destination_ip_2): [log1,log2,log3],
            }        

            the keys are types of (source_ip,destination_ip)
        """
        return_data = dict()
        for log in dataset:
            source_ip = log["source_ip"]
            destination_ip = log["destination_ip"]
            source_ip_destination_ip_pair = (source_ip,destination_ip)
            if source_ip_destination_ip_pair in return_data:
                # if the source ip and destination ip pair already exists, append the log
                print(f"source ip destination ip pair found in return data: {source_ip_destination_ip_pair}")
                return_data[source_ip_destination_ip_pair].append(log)
            else:
                log_list = list()
                log_list.append(log)
                return_data[source_ip_destination_ip_pair] = log_list
        return return_data

    def check_multiple_attacker_on_same_honeypot(self,dataset):
        """
            Different Source IP + Same Destination IP 
            +   src ip == attacker
            +   dest ip == honeypot
            return_data  = {
                "destination_ip_1" : [
                    [source_ip_1,source_ip_2],
                    [log_1,log_2,log_3]
                    ],
            }
        """
        return_data = dict()
        for log in dataset:
            source_ip = log["source_ip"]
            destination_ip = log["destination_ip"]
            # https://stackoverflow.com/questions/1602934/check-if-a-given-key-already-exists-in-a-dictionary
            # for some ds reason, I do not need to call .keys() method
            # check if the source_ip is one the keys in return_data
            if destination_ip in return_data:
                # return_data["10.1.1.2"]
                # print("source ip found")
                # check if if the current destination ip is already inside the destination_ip_list 
                if source_ip in return_data[destination_ip][0]:  
                    # the destinationn ip is not  added  to the list if it is found inside the destination_ip_list
                    print(f"Same Source IP address found in the list: {source_ip}") 
                else:
                    print(f"Adding new source ip to the list: {source_ip}")
                    # add the destination ip to the list if it is NOT found inside destination_ip_list
                    return_data[destination_ip][0].append(source_ip)
                    print(f"new source ip list: {return_data[destination_ip][0]}")
                # append the log to the log list 
                return_data[destination_ip][1].append(log)
            else:
                # create a new key in return_data with the source ip return_data["10.1.1.1"] = {}
                return_data[destination_ip] = list()
                # append the destnation ip as part of a newly declared list return_date["10.1.1.1"] = [192.168.1.1]  
                source_ip_list = list()
                source_ip_list.append(source_ip)
                return_data[destination_ip].append(source_ip_list)
                # append the log as part of a newly declared list return_date["10.1.1.1"] = [[192.168.1.1],[log]]
                log_list = list()
                log_list.append(log)
                return_data[destination_ip].append(log_list)

        return return_data

general_logs = [{
   "capture_date":"2021-01-14 22:31:17",
   "honeynode_name":"dionaea-test",
   "source_ip":"192.168.148.141",
   "source_port":42486,
   "destination_ip":"10.1.1.1",
   "destination_port":22,
   "protocol":"tcp",
   "token":"6efd8740-64c4-4af0-bae5-e5cb41a925a8",
   "raw_logs":"{\"remote_hostname\": \"\", \"local_host\": \"192.168.148.159\", \"local_port\": 22, \"connection_protocol\": \"pcap\", \"remote_host\": \"192.168.148.146\", \"connection_transport\": \"tcp\", \"connection_type\": \"reject\", \"remote_port\": 42486}"
}, {
   "capture_date":"2021-01-14 22:31:17",
   "honeynode_name":"dionaea-test-2",
   "source_ip":"192.168.148.141",
   "source_port":42486,
   "destination_ip":"10.1.1.2",
   "destination_port":22,
   "protocol":"tcp",
   "token":"6efd8740-64c4-4af0-bae5-e5cb41a925a8",
   "raw_logs":"{\"remote_hostname\": \"\", \"local_host\": \"192.168.148.159\", \"local_port\": 22, \"connection_protocol\": \"pcap\", \"remote_host\": \"192.168.148.146\", \"connection_transport\": \"tcp\", \"connection_type\": \"reject\", \"remote_port\": 42486}"
}]


nids_logs = [
    {
   "date":"2021-01-14 22:29:11",
   "token":"6efd8740-64c4-4af0-bae5-e5cb41a925a8",
   "honeynode_name":"dionaea-test",
   "source_ip":"192.168.148.141",
   "source_port":55010,
   "destination_ip":"10.1.1.3",
   "destination_port":3306,
   "priority":2,
   "classification":3,
   "signature":"ET SCAN Suspicious inbound to mySQL port 3306",
   "raw_logs":"{\"iplen\": 45056, \"timestamp\": \"2021/01/14 22:29:10.546420\", \"tos\": 0, \"sensor\": \"6efd8740-64c4-4af0-bae5-e5cb41a925a8\", \"header\": \"1:2010937:3\", \"source_ip\": \"192.168.148.146\", \"classification\": 3, \"ethdst\": \"00:0C:29:B9:81:02\", \"priority\": 2, \"tcpflags\": \"******S*\", \"signature\": \"ET SCAN Suspicious inbound to mySQL port 3306\", \"ttl\": 43, \"proto\": \"TCP\", \"source_port\": 55010, \"tcpack\": \"0x0\", \"destination_port\": 3306, \"destination_ip\": \"192.168.148.159\", \"id\": 51050, \"ethlen\": \"0x3C\", \"ethtype\": \"0x800\", \"dgmlen\": 44, \"ethsrc\": \"00:0C:29:1C:81:D5\", \"tcpseq\": \"0x41AC4EC4\", \"tcpwin\": \"0x4000000\", \"tcplen\": 24}"
},
{
   "date":"2021-01-14 22:29:11",
   "token":"6efd8740-64c4-4af0-bae5-e5cb41a925a8",
   "honeynode_name":"dionaea-test-2",
   "source_ip":"192.168.148.141",
   "source_port":55010,
   "destination_ip":"10.1.1.2",
   "destination_port":3306,
   "priority":2,
   "classification":3,
   "signature":"ET SCAN Suspicious inbound to mySQL port 3306",
   "raw_logs":"{\"iplen\": 45056, \"timestamp\": \"2021/01/14 22:29:10.546420\", \"tos\": 0, \"sensor\": \"6efd8740-64c4-4af0-bae5-e5cb41a925a8\", \"header\": \"1:2010937:3\", \"source_ip\": \"192.168.148.146\", \"classification\": 3, \"ethdst\": \"00:0C:29:B9:81:02\", \"priority\": 2, \"tcpflags\": \"******S*\", \"signature\": \"ET SCAN Suspicious inbound to mySQL port 3306\", \"ttl\": 43, \"proto\": \"TCP\", \"source_port\": 55010, \"tcpack\": \"0x0\", \"destination_port\": 3306, \"destination_ip\": \"192.168.148.159\", \"id\": 51050, \"ethlen\": \"0x3C\", \"ethtype\": \"0x800\", \"dgmlen\": 44, \"ethsrc\": \"00:0C:29:1C:81:D5\", \"tcpseq\": \"0x41AC4EC4\", \"tcpwin\": \"0x4000000\", \"tcplen\": 24}"
}
]

def test_one_attack_multiple_honeypots():
    dc = DataCorrelator(5)
    dataset = dc.get_dataset(general_logs,nids_logs)
    cd = dc.check_one_attacker_attacking_multiple_honeypots(dataset)
    # print(cd.keys())
    for key in cd.keys():
        print(f"Attacker IP: {key}")
        print(f"HoneyPots Being Attacked: {cd[key][0]}")
        print("\n\n\n")
        print(f"log list:{cd[key][1]}")
        print("\n\n\n")

def test_check_one_attacker_attacking_multiple_honeypots():
    dc = DataCorrelator(5)
    dataset = dc.get_dataset(general_logs,nids_logs)
    cd = dc.check_attacker_attacking_same_honeypot_multiple_times(dataset)
    print("\n\n")
    for key in cd.keys():
        print(key[1])

def test_check_multiple_attacker_on_same_honeypot():
    dc = DataCorrelator(5)
    dataset = dc.get_dataset(general_logs,nids_logs)
    cd = dc.check_multiple_attacker_on_same_honeypot(dataset)
    print("\n\n")
    for key in cd.keys():
        print(f"Target IP: {key}")
        print(f"Attacker IP: {cd[key][0]}")
        print("\n\n")
        print(f"Logs: {cd[key][1]}")
        print("\n\n")
# test_check_one_attacker_attacking_multiple_honeypots()
# test_check_multiple_attacker_on_same_honeypot()
test_one_attack_multiple_honeypots()
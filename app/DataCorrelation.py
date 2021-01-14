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
"""
class DataCorrelator():
    def __init__(self,time_window):
        self.time_window = time_window
        """
            +   Time Window can be specified by the user
            +   Pull the logs within this time window and process them
        """
    # def correlate_via_time(self,time_window,data):

    #     print("Time")
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
        """
        """
        1. Get number of unique src ip addresses and store them as keys in a dict
        2. The dict is called src_ip_to_dest_ip, the value will contain the different dest ip addresses

            logs_with_same_source_ip_unique_destination_ip = {
                "src_ip_1" : ["dest_ip_1","dest_ip_2","dest_ip_3" ],
                "src_ip_2" : ["dest_ip_1" ],
                "src_ip_3" : ["dest_ip_1","dest_ip_2","dest_ip_3","dest_ip_4" ]
            }
            logs_with_same_source_ip_unique_destination_ip  = {
                "src_ip_1" : [log_1,log_2,log_3],
                "src_ip_2" : [log_1 ],
                "src_ip_3" : [log_1]
            }
           logs_with_same_source_ip_unique_destination_ip  = {
                "src_ip_1" : [
                        {"dest_ip_1:" log_1},
                        {"dest_ip_2:" log_2},
                        {"dest_ip_3:" log_3},
                "src_ip_2" : [log_1 ],
                "src_ip_3" : [log_1]
            }
        """
        """
        1. Get all the logs with same source ip 
        """
        logs_with_same_source_ip_unique_destination_ip = {}
        for log in dataset:
            source_ip = log["source_ip"]
            destination_ip = log["destination_ip"]
            # https://stackoverflow.com/questions/1602934/check-if-a-given-key-already-exists-in-a-dictionary
            # for some ds reason, I do not need to call .keys() method
            if source_ip in logs_with_same_source_ip_unique_destination_ip:
                print("source ip found")
                # check if there is a log inside the list that has the same destion ip address as log 
                # print(len(logs_with_same_source_ip_unique_destination_ip[source_ip]))
                # print(destination_ip)
                if destination_ip in logs_with_same_source_ip_unique_destination_ip[source_ip]:   
                    print("Same DEST IP FOUND") 
                    print(destination_ip)
                else:
                    logs_with_same_source_ip_unique_destination_ip[source_ip].append({destination_ip: log})
            else:
                logs_with_same_source_ip_unique_destination_ip[source_ip] = []
                logs_with_same_source_ip_unique_destination_ip[source_ip].append({destination_ip: log})
        print(logs_with_same_source_ip_unique_destination_ip[source_ip][0])
        print("\n\n")
        print(logs_with_same_source_ip_unique_destination_ip[source_ip][1])

        return logs_with_same_source_ip_unique_destination_ip

    def check_one_attacker_attacking_same_dest_port_on_multiple_honeypots(self,dataset):
        """
            +   Same src ip address + same dest port + differnt ip address
        """
        print("DEST PORT")

general_logs = [{
   "capture_date":"2021-01-14 22:31:17",
   "honeynode_name":"dionaea-test",
   "source_ip":"192.168.148.146",
   "source_port":42486,
   "destination_ip":"10.1.1.1",
   "destination_port":22,
   "protocol":"tcp",
   "token":"6efd8740-64c4-4af0-bae5-e5cb41a925a8",
   "raw_logs":"{\"remote_hostname\": \"\", \"local_host\": \"192.168.148.159\", \"local_port\": 22, \"connection_protocol\": \"pcap\", \"remote_host\": \"192.168.148.146\", \"connection_transport\": \"tcp\", \"connection_type\": \"reject\", \"remote_port\": 42486}"
}, {
   "capture_date":"2021-01-14 22:31:17",
   "honeynode_name":"dionaea-test-2",
   "source_ip":"192.168.148.146",
   "source_port":42486,
   "destination_ip":"10.1.1.1",
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
   "source_ip":"192.168.148.146",
   "source_port":55010,
   "destination_ip":"10.1.1.1",
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
   "source_ip":"192.168.148.146",
   "source_port":55010,
   "destination_ip":"10.1.1.1",
   "destination_port":3306,
   "priority":2,
   "classification":3,
   "signature":"ET SCAN Suspicious inbound to mySQL port 3306",
   "raw_logs":"{\"iplen\": 45056, \"timestamp\": \"2021/01/14 22:29:10.546420\", \"tos\": 0, \"sensor\": \"6efd8740-64c4-4af0-bae5-e5cb41a925a8\", \"header\": \"1:2010937:3\", \"source_ip\": \"192.168.148.146\", \"classification\": 3, \"ethdst\": \"00:0C:29:B9:81:02\", \"priority\": 2, \"tcpflags\": \"******S*\", \"signature\": \"ET SCAN Suspicious inbound to mySQL port 3306\", \"ttl\": 43, \"proto\": \"TCP\", \"source_port\": 55010, \"tcpack\": \"0x0\", \"destination_port\": 3306, \"destination_ip\": \"192.168.148.159\", \"id\": 51050, \"ethlen\": \"0x3C\", \"ethtype\": \"0x800\", \"dgmlen\": 44, \"ethsrc\": \"00:0C:29:1C:81:D5\", \"tcpseq\": \"0x41AC4EC4\", \"tcpwin\": \"0x4000000\", \"tcplen\": 24}"
}
]

dc = DataCorrelator(5)
dataset = dc.get_dataset(general_logs,nids_logs)
# print(dataset)

cd = dc.check_one_attacker_attacking_multiple_honeypots(dataset)
# print(cd.keys())
# print(cd)
# for src_ip in cd.keys():
#     dest_ip_to_log_list = cd[src_ip]
#     for dest_ip_to_log in dest_ip_to_log_list:
#         print(dest_ip_to_log)
#         print("\n")
        
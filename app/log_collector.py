import hpfeeds
import sys
import json
import requests
from datetime import datetime
from configparser import ConfigParser
import os


# run broker :
# If the aionotify package is installed and the host os is Linux then the broker will automatically reload the JSON file whenever it changes.
# pip3 install aionotify
# hpfeeds-broker -e tcp:port=10000 --auth=auth.json --name=mybroker
basedir = os.path.abspath(os.path.dirname(__file__))
config = ConfigParser()
config.read(os.path.join(basedir, 'heartbeats_server.conf'))

WEB_SERVER_IP = config['WEB-SERVER']['SERVER_IP'] 
WEB_SERVER_PORT = config['WEB-SERVER']['PORT']

GET_NODE_API_ENDPOINT = f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/honeynodes/"

LOG_API_ENDPOINTS = {
    "general_log": f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/general_logs",
    "nids_log": f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/nids_logs",
    "session_log": f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/session_logs"
}
# GENERAL_LOG_API_ENDPOINT = f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/general_logs"

HOST = 'localhost'
PORT = 10000

CHANNELS = [
    "cowrie.sessions",
    "snort.alerts",
    "agave.events",     # for drupot
    "wordpot.events",
    "elastichoney.events",
    "shockpot.events",
    "sticky_elephant.connections", 
    "sticky_elephant.queries",
    "dionaea.connections"
]

IDENT = 'collector'
SECRET = 'collector'


def parse_cowrie_logs(identifier, payload):
    general_log_data_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["peerIP"]
    general_log_data_dict['source_port'] = payload["peerPort"]
    general_log_data_dict['destination_ip'] = payload["hostIP"]
    general_log_data_dict['destination_port'] = payload["hostPort"]
    general_log_data_dict['protocol'] = "tcp"
    general_log_data_dict['token'] = identifier
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return (general_log_data_dict, "general_log")


def parse_elastichoney_logs(identifier, payload):
    general_log_data_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["source"]
    general_log_data_dict['source_port'] = 0
    general_log_data_dict['destination_ip'] = payload["honeypot"]
    general_log_data_dict['destination_port'] = payload["headers"]['host'].split(':')[1]
    general_log_data_dict['protocol'] = "tcp"
    general_log_data_dict['token'] = identifier
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return (general_log_data_dict, 'general_log')


def parse_wordpot_logs(identifier, payload):
    general_log_data_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["source_ip"]
    general_log_data_dict['source_port'] = payload["source_port"]
    general_log_data_dict['destination_ip'] = payload["dest_ip"]
    general_log_data_dict['destination_port'] = payload["dest_port"]
    general_log_data_dict['protocol'] = "tcp"
    general_log_data_dict['token'] = identifier
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return (general_log_data_dict, 'general_log')


def parse_drupot_logs(identifier, payload):
    general_log_data_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["src_ip"]
    general_log_data_dict['source_port'] = payload["src_port"]
    general_log_data_dict['destination_ip'] = payload["dest_ip"]
    general_log_data_dict['destination_port'] = payload["dest_port"]
    general_log_data_dict['protocol'] = "tcp"
    general_log_data_dict['token'] = identifier
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return (general_log_data_dict, 'general_log')


def parse_shockpot_logs(identifier, payload):
    general_log_data_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["source_ip"]
    general_log_data_dict['source_port'] = 0
    general_log_data_dict['destination_ip'] = payload["dest_host"]
    general_log_data_dict['destination_port'] = payload["dest_port"]
    general_log_data_dict['protocol'] = "tcp"
    general_log_data_dict['token'] = identifier
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return (general_log_data_dict, 'general_log')


def parse_sticky_elephant_logs(identifier, payload):
    general_log_data_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["source_ip"]
    general_log_data_dict['source_port'] = payload["source_port"]
    general_log_data_dict['destination_ip'] = payload["dest_ip"]
    general_log_data_dict['destination_port'] = payload["dest_port"]
    general_log_data_dict['protocol'] = "tcp"
    general_log_data_dict['token'] = identifier
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return (general_log_data_dict, 'general_log')
    

def parse_dionaea_connection_logs(identifier, payload):
    general_log_data_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["remote_host"]
    general_log_data_dict['source_port'] = payload["remote_port"]
    general_log_data_dict['destination_ip'] = payload["local_host"]
    general_log_data_dict['destination_port'] = payload["local_port"]
    general_log_data_dict['protocol'] = payload["connection_transport"]
    general_log_data_dict['token'] = identifier
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return (general_log_data_dict, 'general_log')


def parse_snort_nids_logs(identifier, payload):
    nids_log_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    nids_log_dict['date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    nids_log_dict['honeynode_name'] = honeynode_name
    nids_log_dict['source_ip'] = payload['source_ip']
    nids_log_dict['source_port'] = payload['source_port']
    nids_log_dict['destination_ip'] = payload['destination_ip']
    nids_log_dict['destination_port'] = payload['destination_port']
    nids_log_dict['priority'] = int(payload['priority'])
    nids_log_dict['classification'] = int(payload['classification'])
    nids_log_dict['signature'] = payload['signature']
    nids_log_dict['raw_logs'] = json.dumps(payload)

    return (nids_log_dict, 'nids_log')


def process_log_data(identifier, channel, payload):
    log_data = dict()

    if channel == "cowrie.sessions":
        log_data = parse_cowrie_logs(identifier, payload)
    elif channel == "agave.events":
        log_data = parse_drupot_logs(identifier, payload)
    elif channel == "wordpot.events":
        log_data = parse_wordpot_logs(identifier, payload)
    elif channel == "elastichoney.events":
        log_data = parse_elastichoney_logs(identifier, payload)
    elif channel == "shockpot.events":
        log_data = parse_shockpot_logs(identifier, payload)
    elif channel == "sticky_elephant.connections" or channel == "sticky_elephant.queries":
        log_data = parse_sticky_elephant_logs(identifier, payload)
    elif channel == "dionaea.connections":
        log_data = parse_dionaea_connection_logs(identifier, payload)
    elif channel == "snort.alerts":
        log_data = parse_snort_nids_logs(identifier, payload)

    # log_data[0] is the dictionary containing the log's data
    # log_data[1] is the log_type
    result_value = insert_log_to_database(log_data[0], log_data[1])

    if result_value == 0:
        print("log insertion successful")
    else:
        print("log insertion failed")


def get_honeynode_name_by_token(token):
    # call the api /api/v1/honeynodes/<string:token> to retrieve single honeynode
    response = requests.get(GET_NODE_API_ENDPOINT + token)
    honeynode_data = response.json()
    # print(honeynode_data)
    if honeynode_data:
        return honeynode_data[0]['honeynode_name']
    else:
        return " "


def insert_log_to_database(log_data_dict, log_type):
    if log_type not in LOG_API_ENDPOINTS.keys():
        return 0
    api_to_call = LOG_API_ENDPOINTS[log_type]
    headers = {'content-type': 'application/json'}
    response = requests.post(api_to_call, data=json.dumps(log_data), headers=headers)
    print(response.text)
    return 1


def main():
    # print("app passed to log_collector.main >> ")
    # print(app.config)
    hpc = hpfeeds.new(HOST, PORT, IDENT, SECRET)
    print("connected to " + hpc.brokername)


    def on_message(identifier, channel, payload):

        print(f"Identifier : {identifier}")
        print(f"Channel: {channel}")
        print("Payload:")
 
        payload_converted = json.loads(payload.decode())
        # print(type(payload_converted))
        process_log_data(identifier, channel, payload_converted)
        # print(general_log_data)
        # print("\n")

        # store the log to the database
        # insert_general_log_to_database(general_log_data)

    def on_error(payload):
        hpc.stop()


    hpc.subscribe(CHANNELS)
    hpc.run(on_message, on_error)
    print("error occured, aborting...")
    hpc.close()
    return 0


# if __name__ == "__main__":
#    main()
import hpfeeds
import sys
import json
import requests
from datetime import datetime
from configparser import ConfigParser
import os
import random


# run broker :
# If the aionotify package is installed and the host os is Linux then the broker will automatically reload the JSON file whenever it changes.
# pip3 install aionotify
# hpfeeds-broker -e tcp:port=10000 --auth=auth.json --name=mybroker
basedir = os.path.abspath(os.path.dirname(__file__))
config = ConfigParser()
config.read(os.path.join(basedir, 'server.conf'))

WEB_SERVER_IP = config['WEB-SERVER']['SERVER_IP'] 
WEB_SERVER_PORT = config['WEB-SERVER']['PORT']

GET_NODE_API_ENDPOINT = f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/honeynodes/"

LOG_API_ENDPOINTS = {
    "general_log": f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/general_logs",
    "nids_log": f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/snort_logs",
    "session_log": f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/session_logs",
    "latest_bruteforce_log": f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/latest_bruteforce_log",
    "update_bruteforce_log": f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/update_bruteforce_log"
}

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

BRUTE_FORCE_LOG_TIME_WINDOW = 60 * 10  # 10 mins

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
    response = requests.post(api_to_call, data=json.dumps(log_data_dict), headers=headers)
    print(response.text)
    return 1
    

def convert_time_format(time_string):
    # example of the format of time_string: {"2020-12-24T14:31:51.443015Z"}
    # it will be converted to: "2020-12-24 14:31:51"
    return time_string.split(".")[0].replace("T", " ")


def get_latest_cowrie_bruteforce_log(identifier, payload):
    headers = {'content-type': 'application/json'}
    payload['token'] = identifier
    response = requests.post(LOG_API_ENDPOINTS['latest_bruteforce_log'], data=json.dumps(payload), headers=headers)
    print(response.text)
    response_data = response.json()
    if response_data['bruteforce_log_empty'] == True:
        return None
    if response_data['bruteforce_log_empty'] == False and response_data['latest_bruteforce_log'] is not None:
        print("latest bruteforce log ==> ")
        print(response_data['latest_bruteforce_log'])
        return response_data['latest_bruteforce_log']


def update_bruteforce_log(token, source_ip, credentials, end_time):
    data = {
        "token": token,
        "source_ip": source_ip,
        "credentials": credentials,
        "end_time": convert_time_format(end_time)
    }
    headers = {'content-type': 'application/json'}
    response = requests.post(LOG_API_ENDPOINTS['update_bruteforce_log'], data=json.dumps(data), headers=headers)
    print(response.text)


def parse_cowrie_logs(identifier, payload):
    general_log_data_dict = dict()
    session_log_data_dict = None

    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["peerIP"]
    general_log_data_dict['source_port'] = payload["peerPort"]
    general_log_data_dict['destination_ip'] = payload["hostIP"]
    general_log_data_dict['destination_port'] = payload["hostPort"]
    general_log_data_dict['protocol'] = "tcp"
    general_log_data_dict['token'] = identifier
    if 'version' in payload.keys() and payload['version'] is not None:
        # remove the single quote and backslash in the version string
        payload['version'] = payload['version'].replace("\\", "").replace("\'", "")
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    if payload['loggedin'] is not None:  # meaning this is a session log
        session_log_data_dict = dict()
        session_log_data_dict['token'] = identifier
        session_log_data_dict['honeynode_name'] = honeynode_name
        session_log_data_dict['source_ip'] = payload["peerIP"]
        session_log_data_dict['source_port'] = payload["peerPort"]
        session_log_data_dict['destination_ip'] = payload["hostIP"]
        session_log_data_dict['destination_port'] = payload["hostPort"]
        session_log_data_dict['commands'] = payload['commands']
        session_log_data_dict['logged_in'] = payload['loggedin']
        session_log_data_dict['start_time'] = convert_time_format(payload['startTime'])
        session_log_data_dict['end_time'] = convert_time_format(payload['endTime'])
        session_log_data_dict['session'] = payload['session']
        session_log_data_dict['urls'] = payload['urls']
        session_log_data_dict['credentials'] = payload['credentials']
        session_log_data_dict['version'] = payload['version']
        session_log_data_dict['hashes'] = payload['hashes']
        session_log_data_dict['unknown_commands'] = payload['unknownCommands']
        print(session_log_data_dict)
        return [(general_log_data_dict, "general_log"), (session_log_data_dict, "session_log")]

    elif len(payload['credentials']) > 0:  # meaning this is a bruteforce log
        latest_bruteforce_log = json.loads(get_latest_cowrie_bruteforce_log(identifier, payload))

        print(convert_time_format(payload['endTime']))
        print(latest_bruteforce_log['end_time'])
        time_elapsed_since_last_brutefoce_log = datetime.strptime(convert_time_format(payload['endTime']), "%Y-%m-%d %H:%M:%S") - datetime.strptime(latest_bruteforce_log['end_time'], "%Y-%m-%d %H:%M:%S")

        if latest_bruteforce_log is None or (time_elapsed_since_last_brutefoce_log.total_seconds() > BRUTE_FORCE_LOG_TIME_WINDOW):  # meaning this is the first bruteforce log associated with this cowrie honeypot
            session_log_data_dict = dict()
            session_log_data_dict['token'] = identifier
            session_log_data_dict['honeynode_name'] = honeynode_name
            session_log_data_dict['source_ip'] = payload["peerIP"]
            session_log_data_dict['source_port'] = payload["peerPort"]
            session_log_data_dict['destination_ip'] = payload["hostIP"]
            session_log_data_dict['destination_port'] = payload["hostPort"]
            session_log_data_dict['commands'] = payload['commands']
            session_log_data_dict['logged_in'] = payload['loggedin']
            session_log_data_dict['start_time'] = convert_time_format(payload['startTime'])
            session_log_data_dict['end_time'] = convert_time_format(payload['endTime'])
            session_log_data_dict['session'] = payload['session']
            session_log_data_dict['urls'] = payload['urls']
            session_log_data_dict['credentials'] = payload['credentials']
            session_log_data_dict['version'] = payload['version']
            session_log_data_dict['hashes'] = payload['hashes']
            session_log_data_dict['unknown_commands'] = payload['unknownCommands']
            print(session_log_data_dict)
            return [(general_log_data_dict, "general_log"), (session_log_data_dict, "session_log")]

        elif time_elapsed_since_last_brutefoce_log.total_seconds() <= BRUTE_FORCE_LOG_TIME_WINDOW:
            print(type(latest_bruteforce_log['credentials']))
            print(type(payload['credentials']))
            update_bruteforce_log(identifier, payload['peerIP'], json.loads(latest_bruteforce_log['credentials']) + payload['credentials'], payload['endTime'])
            return []

    return [(general_log_data_dict, "general_log")]


def parse_elastichoney_logs(identifier, payload):
    general_log_data_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["source"]
    general_log_data_dict['source_port'] = random.randint(20000, 30000)
    general_log_data_dict['destination_ip'] = payload["honeypot"]
    general_log_data_dict['destination_port'] = payload["headers"]['host'].split(':')[1]
    general_log_data_dict['protocol'] = "tcp"
    general_log_data_dict['token'] = identifier
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return [(general_log_data_dict, 'general_log')]


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
    if "username" in payload.keys():
        payload["username"] = payload["username"].replace("'", "").replace("\\", "")
    if "password" in payload.keys():
        payload["password"] = payload["password"].replace("'", "").replace("\\", "")

    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return [(general_log_data_dict, 'general_log')]


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
    if "agave_username" in payload.keys():
        payload['agave_username'] = payload["agave_username"].replace("'", "").replace("\\", "")

    if "agave_password" in payload.keys():
        payload['agave_password'] = payload["agave_password"].replace("'", "").replace("\\", "")
    general_log_data_dict['raw_logs'] = json.dumps(payload)

    return [(general_log_data_dict, 'general_log')]


def parse_shockpot_logs(identifier, payload):
    general_log_data_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    general_log_data_dict['capture_date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    general_log_data_dict['honeynode_name'] = honeynode_name
    general_log_data_dict['source_ip'] = payload["source_ip"]
    general_log_data_dict['source_port'] = random.randint(20000, 30000)
    general_log_data_dict['destination_ip'] = payload["dest_host"]
    general_log_data_dict['destination_port'] = payload["dest_port"]
    general_log_data_dict['protocol'] = "tcp"
    general_log_data_dict['token'] = identifier
    general_log_data_dict['raw_logs'] = json.dumps(payload).replace('\\', '\\\\').replace("\'", "").replace("\\\"", "")

    return [(general_log_data_dict, 'general_log')]


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
    if "query" in payload.keys():
        payload["query"] = payload["query"].replace("'", '').replace('"', "").replace("\\", "").replace("\n", "")
    general_log_data_dict['raw_logs'] = json.dumps(payload)
    # general_log_data_dict['raw_logs'] = json.dumps(payload)

    return [(general_log_data_dict, 'general_log')]
    

def parse_dionaea_connection_logs(identifier, payload):
    if len(payload['local_host']) == 0 or payload['local_port'] == 0:
        return []

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

    return [(general_log_data_dict, 'general_log')]


def parse_snort_nids_logs(identifier, payload):
    if payload['source_ip'] == '0.0.0.0' or payload['destination_ip'].split('.')[-1] == '254':
        return []


    nids_log_dict = dict()
    honeynode_name = get_honeynode_name_by_token(identifier)

    nids_log_dict['date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    nids_log_dict['token'] = identifier
    nids_log_dict['honeynode_name'] = honeynode_name
    nids_log_dict['source_ip'] = payload['source_ip']
    nids_log_dict['source_port'] = payload['source_port']
    nids_log_dict['destination_ip'] = payload['destination_ip']
    nids_log_dict['destination_port'] = payload['destination_port']
    nids_log_dict['priority'] = int(payload['priority'])
    nids_log_dict['classification'] = int(payload['classification'])
    nids_log_dict['signature'] = payload['signature']
    nids_log_dict['raw_logs'] = json.dumps(payload)

    return [(nids_log_dict, 'nids_log')]


def process_log_data(identifier, channel, payload):
    log_data_list = list()

    if channel == "cowrie.sessions":
        log_data_list = parse_cowrie_logs(identifier, payload)
    elif channel == "agave.events":
        log_data_list = parse_drupot_logs(identifier, payload)
    elif channel == "wordpot.events":
        log_data_list = parse_wordpot_logs(identifier, payload)
    elif channel == "elastichoney.events":
        log_data_list = parse_elastichoney_logs(identifier, payload)
    elif channel == "shockpot.events":
        log_data_list = parse_shockpot_logs(identifier, payload)
    elif channel == "sticky_elephant.connections" or channel == "sticky_elephant.queries":
        log_data_list = parse_sticky_elephant_logs(identifier, payload)
    elif channel == "dionaea.connections":
        log_data_list = parse_dionaea_connection_logs(identifier, payload)
    elif channel == "snort.alerts":
        log_data_list = parse_snort_nids_logs(identifier, payload)

    for log_data in log_data_list:
        # log_data[0] is the dictionary containing the log's data
        # log_data[1] is the log_type
        result_value = insert_log_to_database(log_data[0], log_data[1])

        if result_value == 0:
            print("log insertion failed")
            
        else:
            print("log insertion successful")


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
        process_log_data(identifier, channel, payload_converted)


    def on_error(payload):
        hpc.stop()


    hpc.subscribe(CHANNELS)
    hpc.run(on_message, on_error)
    print("error occured, aborting...")
    hpc.close()
    return 0


# if __name__ == "__main__":
#    main()
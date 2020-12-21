import socket
import uuid
import json
def send_signal_honeynode_kill(ip_addr,port):
     # Signal/Send command to the honey node @ ip_addr to kill 
    print(f"\nkilling {ip_addr}\n")
    
    kill_signal= {
        'command': "KILL"
    }
    kill_signal_json = json.dumps(kill_signal)
    kill_signal_encoded = kill_signal_json.encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as hbsocket:
        for _ in range(3):
            hbsocket.sendto(kill_signal_encoded, (ip_addr,port))


def send_signal_heartbeats_server_repopulate(ip_addr,port):
    # signal the heartbeat server to repopulate the heartbeat dictionary
    populate_signal= {
        'msg': "POPULATE"
    }
    populate_signal_json = json.dumps(populate_signal)
    populate_signal_encoded = populate_signal_json.encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as hbsocket:
        hbsocket.sendto( populate_signal_encoded, (ip_addr,port))

def send_signal_honeynode_add_node(ip_addr,port):
    add_node_signal={
        'command' : 'ADD_NODE'
    }
    add_node_signal_json = json.dumps(add_node_signal)
    add_node_signal_encoded = add_node_signal_json.encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as hbsocket:
        hbsocket.sendto(add_node_signal_encoded, (ip_addr,port))
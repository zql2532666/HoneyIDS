import yaml, json, requests
from time import sleep
from DbAccess import *
from gevent.pywsgi import WSGIServer
from flask_mysqldb import MySQL
from flask import Flask, render_template, request, jsonify, abort, redirect, url_for, flash,send_file
import os
from HpfeedsDB import *
import subprocess
from configparser import ConfigParser
import socket
import uuid
from signal import *

app = Flask(__name__,
            static_url_path='', 
            static_folder='static',
            template_folder='templates')
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

basedir = os.path.abspath(os.path.dirname(__file__))

# Heartbeats Server and HoneyNode Configuration
config = ConfigParser()
config.read(os.path.join(basedir, 'heartbeats_server.conf'))

HBPORT = int(config['HEARTBEATS']['SERVER_HB_PORT']) 
HELLO_INTERVAL = int(config['HEARTBEATS']['HELLO_INTERVAL'])   
DEAD_INTERVAL = int(config['HEARTBEATS']['DEAD_INTERVAL'])   
WEB_SERVER_IP = config['WEB-SERVER']['SERVER_IP'] 
WEB_SERVER_PORT = config['WEB-SERVER']['PORT']
HONEYNODE_COMMAND_PORT = int(config['HONEYNODE']['COMMAND_PORT'])

# Configure DB
db = yaml.load(open(os.path.join(basedir, 'db.yaml')), Loader=yaml.SafeLoader)
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']
app.config['HPFEEDS_DATABASE_PATH'] = os.path.join(basedir, 'sqlite.db')

# run hpfeeds broker, this will also create the sqlite.db file in the current dir if it doesn't exist
hpfeeds_broker_process = subprocess.Popen(["hpfeeds-broker", "-e", "tcp:port=10000"], stdout=subprocess.PIPE, cwd=basedir)

# Initialise Database
db_access = DbAccess(app)

# Initialize Hpfeeds credential database
hpfeeds_db = HPfeedsDB(app.config['HPFEEDS_DATABASE_PATH'])

# For testing purposes with jinja. Remove later
# Usage: {{ mdebug("whatever to print here") }}
@app.context_processor
def utility_functions():
    def print_in_console(message):
        print(str(message))

    return dict(mdebug=print_in_console)

@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error=str(e)), 404

""" 
API Routes for web pages
Author: Aaron
"""

@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html", title="Dashboard V1")

@app.route("/index2")
def index2():
    return render_template("index2.html", title="Dashboard V2")

@app.route("/index3")
def index3():
    return render_template("index3.html", title="Dashboard V3")

@app.route("/deploy", methods=['GET', 'POST'])
def deploy():
    return render_template("deploy.html", title="Honeypot Deployment")

@app.route("/nodes")
def nodes():
    return render_template("nodes.html", title="Nodes")

@app.route("/addnode", methods=['GET', 'POST'])
def add_node():

    if request.method == 'POST':
        # do stuff when the form is submitted
        #node_name = request.form['nodename']
        ip_addr = request.form['ipaddress']
        
        if(ip_addr):
            send_signal_honeynode_add_node(ip_addr,HONEYNODE_COMMAND_PORT)
            send_signal_heartbeats_server_repopulate(WEB_SERVER_IP,HBPORT)

            flash(u'Node successfully added.', 'success')
        else:
            flash(u'Node not added.', 'danger')
        
        # redirect to end the POST handling
        return ('', 204)
        #return redirect(url_for('nodes'))

    return render_template("addnode.html", title="Add Node")

@app.route("/deactivatenode", methods=['GET', 'POST'])
def kill_node():

    if request.method == 'POST':
        # do stuff when the form is submitted
        ip_addr = request.form['selectkill']

        if(ip_addr):
           
            # kill_signal_json = json.dumps(kill_signal)
            # kill_signal_encoded = kill_signal_json.encode('utf-8')
            # with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as hbsocket:
            #     for _ in range(3):
            #         hbsocket.sendto(kill_signal_encoded, (ip_addr,HONEYNODE_COMMAND_PORT))

            # sleep(DEAD_INTERVAL)
            print("killing now..")
            send_signal_honeynode_kill(ip_addr, HONEYNODE_COMMAND_PORT)
            flash(u'Node successfully killed.', 'success')
        else:
            flash(u'Erorr occurred.', 'danger')
        
        # redirect to end the POST handling
        return ('', 204)
        #return redirect(url_for('kill_node'))

    return render_template("killnode.html", title="Deactivate Node")

@app.context_processor
def list_nodes_for_web():
    try:
        list_nodes = json.loads(db_access.retrieve_all_active_nodes())
    except Exception as e:
        list_nodes = {}
    return dict(list_nodes=list_nodes)

@app.route("/log", methods=['GET', 'POST'])
def log():

    return render_template("log.html", title="General Logs")

@app.route("/sessionlog", methods=['GET', 'POST'])
def session_log():

    return render_template("sessionlog.html", title="Session Logs")

@app.route("/snortlog", methods=['GET', 'POST'])
def snort_log():

    return render_template("snortlog.html", title="NIDS Logs")

@app.route("/malwarelog", methods=['GET', 'POST'])
def malware_log():

    return render_template("malwarelog.html", title="Malware Logs")

######################################## API CALLS ############################################
""" 
API Routes for Log
Author: Aaron
"""

# Retrieve all general logs for datatable
@app.route("/api/v1/general_logs/datatables", methods=['GET'])
def retrieve_all_general_logs_for_datatables():

    datatable_dict = dict()
    datatable_dict["data"] = json.loads(db_access.retrieve_all_general_logs())

    return datatable_dict

# Retrieve all nids logs for datatable
@app.route("/api/v1/nids_logs/datatables", methods=['GET'])
def retrieve_all_nids_logs_for_datatables():

    datatable_dict = dict()
    datatable_dict["data"] = json.loads(db_access.retrieve_all_nids_logs())

    return datatable_dict
    
""" 
API Routes for HoneyNode Operations
Author: Aaron
"""

# Deactivate node
# @app.route("/api/v1/deactivate/<string:token>", methods=['PUT'])
# def deactivate_node(token):
#     if token:

#         ###### call heartbeat server ######

#         return jsonify({'success': True}), 200
#     else:
#         return abort(404, "Token not specified")

    

# Uncomment for testing
# @app.route("/test", methods=['GET', 'POST'])
# def test():
#     return render_template("test.html")

# CRUD endpoints
# Retrieve all honeynodes
@app.route("/api/v1/honeynodes/", methods=['GET'])
def retrieve_all_nodes():
    return db_access.retrieve_all_nodes()

# Retrieve all honeynodes
@app.route("/api/v1/honeynodes/datatables", methods=['GET'])
def retrieve_all_nodes_for_datatables():

    datatable_dict = dict()
    data = db_access.retrieve_all_nodes()
    if data == {}:
        datatable_dict["data"] = data
    else:
        datatable_dict["data"] = json.loads(data)

    return datatable_dict

#Retrieve all honeynodes for heartbeat server
@app.route("/api/v1/heartbeats/", methods=['GET'])
def retrieve_all_nodes_for_heartbeat():

    return db_access.retrieve_all_nodes_for_heartbeat()

#Retrieve single honeynode
@app.route("/api/v1/honeynodes/<string:token>", methods=['GET'])
def retrieve_node(token):

    return db_access.retrieve_node(token)

# Create honeynode
# Change accordingly with derek's data
# Current data format to insert
# {
#        "honeynode_name" : "test",
#        "ip_addr" : "192.168.1.2",
#        "subnet_mask" : "255.255.255.0",
#        "honeypot_type" : "test",
#        "nids_type" : "null",
#        "no_of_attacks" : "2",
#        "date_deployed" : "2020-01-01 10:10:10",
#        "heartbeat_status" : "down",
#        "last_heard" : "idk",
#        "token" : "2"
# }
@app.route("/api/v1/honeynodes/", methods=['POST'])
def create_node():

    if not request.json or not 'token' in request.json:
        abort(400)

    resultValue = db_access.create_node(request.json)

    if resultValue == 0:
        abort(404)

    print(request.json)
    # abort if 'honeypot_type' and 'nids_type' are not in the request 
    if not all(x in hpfeeds_db.hpfeeds_channels.keys() for x in [request.json['honeypot_type'], request.json['nids_type']]):
        abort(400)

    # add the honeynode's hpfeeds credentials to the sqlite database
    hpfeeds_identifier = request.json['token']
    hpfeeds_secret = request.json['token']
    honeypot_type = request.json['honeypot_type']
    nids_type = request.json['nids_type']
    hpfeeds_update_result = hpfeeds_db.add_honeynode_credentials(hpfeeds_identifier, hpfeeds_secret, honeypot_type, nids_type)

    if hpfeeds_update_result is None:
        abort(404)

    # signal the heartbeat server to repopulate the heartbeat dictionary
    # populate_signal= {
    #     'msg': "POPULATE"
    # }
    # populate_signal_json = json.dumps(populate_signal)
    # populate_signal_encoded = populate_signal_json.encode('utf-8')
    # with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as hbsocket:
    #     hbsocket.sendto( populate_signal_encoded, (WEB_SERVER_IP,HBPORT))
    send_signal_heartbeats_server_repopulate(WEB_SERVER_IP,HBPORT)
    return jsonify({'success': True}), 201


# Update honeynode
@app.route("/api/v1/honeynodes/<string:token>", methods=['PUT'])
def update_node(token):

    if not request.json or not token:
        abort(400)
    
    resultValue = db_access.update_node(request.json, token)

    if resultValue == 0:
        abort(404, "no values inserted")

    return jsonify({'success': True}), 200

# Update honeynodes for heartbeat
@app.route("/api/v1/heartbeats", methods=['POST'])
def update_node_for_heartbeat():
    print("-----heartbeat status is updated----")
    print(request.json)
    if not request.json:
        abort(400, "Invalid Data")
    
    try:
        for token in request.json:
            print(token)
            print(request.json[token])
            print("\n\n")
            db_access.update_node_heartbeat_status(token, request.json[token])

    except Exception as e:
        abort(404, e)

    return jsonify({'success': True}), 200

# Delete honeynode
@app.route("/api/v1/honeynodes/<string:token>", methods=['DELETE'])
def delete_node(token):

    if not token:
        abort(400)

    resultValue = db_access.delete_node(token)

    if resultValue == 0:
        flash(u'Node not deleted.', 'danger')
    else:
        flash(u'Node successfully deleted.', 'success')

    # redirect to end the POST handling
    return redirect(url_for('nodes'))
    #return jsonify({'success': True}), 200

""" 
API ROUTES FOR DEPLOYMENT SCRIPTS  
The API Routes are soley dedicated for serving deployment scripts
Author: Derek

Logical flow should be as follow,
HTTP GET /api/v1/deploy/deployment_script/honeyagent
HTTP GET /api/v1/deploy/deployment_script/honeyagent_conf_file
HTTP GET /api/v1/deploy/deployment_script/ [HONEYPOT TYPE DESIRED]

"""
@app.route("/api/v1/deploy/generate_deployment_command", methods=['POST'])
def generate_deployment_command():
    if not request.json:
        abort(400)
    # print(request.json)
    # print(type(request.json))
    honeynode_name = request.json['honeynode_name']
    honeypot_type = request.json['honeypot_type']
    # honeypot_script_api = f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/deploy/deployment_script/{honeypot_type}"
    # honeypot_script_output_file = f"deploy_{honeypot_type}.sh"
    # nids_script_api = f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/deploy/deployment_script/snort"
    # nids_script_output_file = f"deploy_snort.sh"

    main_script_api=f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/v1/deploy/deployment_script/main"
    main_script_output_file = f"main.sh"
    token = uuid.uuid4()
    # deployment_cmd = f"""
    # sudo wget {honeypot_script_api} -O {honeypot_script_output_file} &&
    # sudo wget {nids_script_api} -O {nids_script_output_file} &&
    # sudo chmod +x {honeypot_script_output_file} {nids_script_output_file} &&
    # sudo ./{honeypot_script_output_file} {WEB_SERVER_IP} {token} {honeynode_name} &&
    # sudo ./{nids_script_output_file}
    # """

    deployment_cmd = f"""
    sudo wget {main_script_api} -O {main_script_output_file} && sudo bash {main_script_output_file} {WEB_SERVER_IP} {WEB_SERVER_PORT} {token} {honeynode_name} {honeypot_type}
    """
    return jsonify(deployment_cmd.strip()), 200

@app.route("/api/v1/deploy/deployment_script/main", methods=['GET'])
def send_deployment_script_main():
    return send_file(os.path.join(basedir, "deployment_scripts/main.sh"))

@app.route("/api/v1/deploy/deployment_script/honeyagent", methods=['GET'])
def send_deployment_script_honeyagent():
    return send_file(os.path.join(basedir, "deployment_scripts/honeyagent.py"))

@app.route("/api/v1/deploy/deployment_script/honeyagent_conf_file", methods=['GET'])
def send_deployment_script_honeyagent_conf():
    return send_file(os.path.join(basedir, "deployment_scripts/honeyagent.conf"))

@app.route("/api/v1/deploy/deployment_script/cowrie", methods=['GET'])
def send_deployment_script_cowrie():
    return send_file(os.path.join(basedir, "deployment_scripts/deploy_cowrie.sh"))

@app.route("/api/v1/deploy/deployment_script/dionaea", methods=['GET'])
def send_deployment_script_dionaea():
    return send_file(os.path.join(basedir, "deployment_scripts/deploy_dionaea.sh"))

@app.route("/api/v1/deploy/deployment_script/drupot", methods=['GET'])
def send_deployment_script_drupot():
    return send_file(os.path.join(basedir, "deployment_scripts/deploy_drupot.sh"))

@app.route("/api/v1/deploy/deployment_script/elastichoney", methods=['GET'])
def send_deployment_script_elastichoney():
    return send_file(os.path.join(basedir, "deployment_scripts/deploy_elastichoney.sh"))

@app.route("/api/v1/deploy/deployment_script/shockpot", methods=['GET'])
def send_deployment_script_shockpot():
    return send_file(os.path.join(basedir, "deployment_scripts/deploy_shockpot.sh"))

@app.route("/api/v1/deploy/deployment_script/snort", methods=['GET'])
def send_deployment_script_snort():
    return send_file(os.path.join(basedir, "deployment_scripts/deploy_snort.sh"))

@app.route("/api/v1/deploy/deployment_script/sticky_elephant", methods=['GET'])
def send_deployment_script_sticky_elephant():
    return send_file(os.path.join(basedir, "deployment_scripts/deploy_sticky_elephant.sh"))

@app.route("/api/v1/deploy/deployment_script/wordpot", methods=['GET'])
def send_deployment_script_wordpot():
    return send_file(os.path.join(basedir, "deployment_scripts/deploy_wordpot.sh"))


# API ROUTE FOR THE CLEAN VM OVA FILE
@app.route("/api/v1/deploy/honeyids-vm.ova", methods=['GET'])
def send_honeyids_vm_ova():
    return send_file(os.path.join(basedir, "vm_ova/honeyids-vm.ova"))




if __name__ == "__main__":
    try:
        http_server = WSGIServer(('0.0.0.0', 5000), app)
        app.debug = True
        print('Waiting for requests.. ')
        http_server.serve_forever()
    except:
        hpfeeds_broker_process.terminate()
        print("Exception")


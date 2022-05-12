import yaml, json, requests
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from time import sleep
from DbAccess import *
from gevent.pywsgi import WSGIServer
from flask_mysqldb import MySQL
from flask import Flask, render_template, request, jsonify, abort, redirect, url_for, flash, send_file, session
import os
from HpfeedsDB import *
import subprocess
from configparser import ConfigParser
import socket
import uuid
from signal import *
from virus_total import *
from DataCorrelation import *
import pyminizip
import warnings
import base64
import ast
from threading import Thread
import log_collector


warnings.filterwarnings("ignore", category=DeprecationWarning) 

app = Flask(__name__,
            static_url_path='', 
            static_folder='static',
            template_folder='templates')
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

basedir = os.path.abspath(os.path.dirname(__file__))

# Heartbeats Server and HoneyNode Configuration
config = ConfigParser()
config.read(os.path.join(basedir, 'server.conf'))

HBPORT = int(config['HEARTBEATS']['SERVER_HB_PORT']) 
HELLO_INTERVAL = int(config['HEARTBEATS']['HELLO_INTERVAL'])   
DEAD_INTERVAL = int(config['HEARTBEATS']['DEAD_INTERVAL'])   
WEB_SERVER_IP = config['WEB-SERVER']['SERVER_IP'] 
WEB_SERVER_PORT = config['WEB-SERVER']['PORT']
HONEYNODE_COMMAND_PORT = int(config['HONEYNODE']['COMMAND_PORT'])

ZIPPED_PASSWORD = config['COMPRESSION']['PASSWORD']
COMPRESSION_LEVEL = int(config['COMPRESSION']['COMPRESSION_LEVEL'])

VT_API_KEY = config['VIRUSTOTAL']['API_KEY']

# Configure DB
db = yaml.load(open(os.path.join(basedir, 'db.yaml')), Loader=yaml.SafeLoader)
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']
app.config['HPFEEDS_DATABASE_PATH'] = os.path.join(basedir, 'sqlite.db')

# run hpfeeds broker, this will also create the sqlite.db file in the current dir if it doesn't exist
# hpfeeds_broker_process = subprocess.Popen(["hpfeeds-broker", "-e", "tcp:port=10000"], stdout=subprocess.PIPE, cwd=basedir)

# Initialise Database
db_access = DbAccess(app)

# Initialize Hpfeeds credential database
hpfeeds_db = HPfeedsDB(app.config['HPFEEDS_DATABASE_PATH'])

@app.errorhandler(404)
def resource_not_found():
    return render_template("404.html", title="404 Error Page")

""" 
User Authentication Routes
Author: Aaron
"""

# Decorator for registering routes for login (Usage: @app.register_login)
def register_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        # Check if user is loggedin
        if 'loggedin' not in session:
            # User not logged in, redirect to login page
            flash(u'Log in first', 'danger')
            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return decorated_function

# Decorator to disable certain routes (Usage: @app.disable)
def disable(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        return abort(500)

    return decorated_function

@app.route("/")
@app.route('/login')
def login():
    return render_template("login.html")

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')

    user = json.loads(db_access.check_user_exists(email))

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if len(user) != 1 or not check_password_hash(user[0]['password'], password):
        flash(u'Please check your login details and try again.', 'danger')
        return redirect(url_for('login')) # if the user doesn't exist or password is wrong, reload the page

    # Create session data, we can access this data in other routes
    session['loggedin'] = True
    session['id'] = user[0]['id']
    session['name'] = user[0]['name'].title()
    session['email'] = user[0]['email']

    # if the above check passes, then we know the user has the right credentials
    return redirect(url_for('index'))

@app.route('/changepassword')
@register_login
def changepassword():
    return render_template("changepassword.html", title="Change Password")

@app.route('/changepassword', methods=['POST'])
def changepassword_post():
    email = session['email']
    password = request.form.get('password')

    if(db_access.update_password(generate_password_hash(password, method='sha256'), email) == 0):
        flash(u'Error occured', 'danger')
        return redirect(url_for('changepassword'))

    flash(u'Password Changed', 'success')
    return redirect(url_for('changepassword'))

@app.route('/signup')
@disable
def signup():
    return render_template("register.html")

@app.route('/signup', methods=['POST'])
@disable
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = json.loads(db_access.check_user_exists(email))
    if len(user) == 1: # if a user is found, we want to redirect back to signup page so user can try again
        flash(u'Email address already exists', 'danger')
        return redirect(url_for('signup'))

    if(db_access.insert_user(email, name, generate_password_hash(password, method='sha256')) == 0):
        flash(u'Error occured', 'danger')
        return redirect(url_for('signup'))

    flash(u'Successfully registered', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
@register_login
def logout():

    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('name', None)
    session.pop('email', None)

    # Redirect to login page
    return redirect(url_for('login'))

""" 
API Routes for web pages
Author: Aaron
"""

@app.route("/index")
@register_login
def index():
    return render_template("index.html", title="Dashboard")

@app.route("/index2")
@register_login
def index2():
    return render_template("index2.html", title="Data Correlation")

@app.route("/deploy", methods=['GET', 'POST'])
@register_login
def deploy():
    return render_template("deploy.html", title="Honey Node Deployment", web_server_ip=WEB_SERVER_IP)

@app.route("/nodes")
@register_login
def nodes():
    return render_template("nodes.html", title="Nodes Listing")

@app.route("/addnode", methods=['GET', 'POST'])
@register_login
def add_node():

    if request.method == 'POST':
        # do stuff when the form is submitted
        #node_name = request.form['nodename']
        ip_addr = request.form['ipaddress']
        
        if(ip_addr):
            send_signal_honeynode_add_node(ip_addr,HONEYNODE_COMMAND_PORT)
            send_signal_heartbeats_server_repopulate(WEB_SERVER_IP,HBPORT)

            flash(u'Node Activation Signal Sent Sucessfully', 'success')
        else:
            flash(u'Node Not Added.', 'danger')
        
        # redirect to end the POST handling
        return ('', 204)
        #return redirect(url_for('nodes'))

    return render_template("addnode.html", title="Add Node")

@app.route("/deactivatenode", methods=['GET', 'POST'])
@register_login
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
            flash(u'Node Kill Signal Sent Successfully', 'success')
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
@register_login
def log():

    return render_template("log.html", title="Honeypot Logs")

@app.route("/sessionlog", methods=['GET', 'POST'])
@register_login
def session_log():

    return render_template("sessionlog.html", title="Session Logs")

@app.route("/snortlog", methods=['GET', 'POST'])
@register_login
def snort_log():

    return render_template("snortlog.html", title="NIDS Logs")

@app.route("/malwarelog", methods=['GET', 'POST'])
@register_login
def malware_log():

    return render_template("malwarelog.html", title="Malware Logs")

######################################## API CALLS ############################################
""" 
API Routes for Log
Author: Aaron
"""

# Retrieve all virus total logs for datatable
@app.route("/api/v1/virus_total_logs/datatables", methods=['GET'])
def retrieve_all_virus_total_logs_for_datatables():
    datatable_dict = dict()
    data = db_access.retrieve_all_virus_total_logs()
    if data == {}:
        datatable_dict["data"] = data
    else:
        datatable_dict["data"] = json.loads(data)

    return datatable_dict

# Retrieve all general logs for datatable
@app.route("/api/v1/general_logs/datatables", methods=['GET'])
def retrieve_all_general_logs_for_datatables():
    datatable_dict = dict()
    data = db_access.retrieve_all_general_logs()
    if data == {}:
        datatable_dict["data"] = data
    else:
        datatable_dict["data"] = json.loads(data)
    return datatable_dict

# Retrieve all nids logs for datatable
@app.route("/api/v1/nids_logs/datatables", methods=['GET'])
def retrieve_all_nids_logs_for_datatables():
    datatable_dict = dict()
    data = db_access.retrieve_all_nids_logs()
    if data == {}:
        datatable_dict["data"] = data
    else:
        datatable_dict["data"] = json.loads(data)

    return datatable_dict

# Retrieve all session logs for datatable
@app.route("/api/v1/session_logs/datatables", methods=['GET'])
def retrieve_all_session_logs_for_datatables():
    datatable_dict = dict()
    data = db_access.retrieve_all_session_logs()
    if data == {}:
        datatable_dict["data"] = data
    else:
        datatable_dict["data"] = json.loads(data)

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
@app.route("/api/v1/honeynodes", methods=['GET'])
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
    # db_access = DbAccess(app)

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
    # db_access = DbAccess(app)

    if not token:
        abort(400)

    resultValue = db_access.delete_node(token)
    # sleep(3)

    if resultValue == 0:
        flash(u'Node not deleted.', 'danger')
    else:
        send_signal_heartbeats_server_repopulate(WEB_SERVER_IP,HBPORT)
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


@app.route("/api/v1/deploy/deployment_script/watchdog", methods=['GET'])
def send_deployment_script_watchdog():
    return send_file(os.path.join(basedir, "deployment_scripts/dionaea_binary_uploader.py"))

# Issues with downloading malware file
@app.route("/api/v1/virus_total_logs/dionaea_malware_file/<string:token>/<string:path>", methods=['GET'])
def send_dionaea_malware_file(token, path):
    return send_file(os.path.join(basedir, "dionaea_malware_files/" + token + "/" + path))

# API ROUTE FOR THE CLEAN VM OVA FILE
@app.route("/api/v1/deploy/honeyids-vm.ova", methods=['GET'])
def send_honeyids_vm_ova():
    return send_file(os.path.join(basedir, "vm_ova/honeyids-vm.ova"))


""" 
API Route for dionaea virus total logs
"""
@app.route('/api/v1/dionaea-binary-upload', methods=['POST'])
def handle_dionaea_upload():
    print("/api/v1/dionaea-binary-upload")
    if request.json:
        malware_file_base64 = request.json['file'].encode('utf-8')
        malware_file_binary = base64.b64decode(malware_file_base64)
        md5 = request.json['md5']
        token = request.json['token']
        time = request.json['time']

        # generate dir path
        dest_dir_path = os.path.join(basedir, f"dionaea_malware_files/{token}/")    
        dest_file_path = os.path.join(dest_dir_path, f"{time}_{md5}")
        # relative_zipped_file_path will be stored in the database, needs to os.path.join when pulled from database
        relative_zipped_file_path = f"dionaea_malware_files/{token}/{time}_{md5}.zip"
        zip_file = f"{dest_file_path}.zip"
        print(f"relative_zipped_file_path: {relative_zipped_file_path}")
        vt_data = vt_request(md5,VT_API_KEY)
        vt_resp = int(vt_data.get("response_code"))
        # insert file path + token here --> will be stored in the database
        vt_data["zipped_file_path"] = relative_zipped_file_path
        vt_data["token"] = token
        vt_data["time_at_file_received"] = time
        vt_data["zipped_file_password"] = ZIPPED_PASSWORD
        # response code == 1 means the hash is found on virus total
        if vt_resp == 1 :
            print("The hash can be found on Virus Total")
            # database function call here 
            result_value = db_access.insert_vt_log(vt_data)
            # result_value = db_access.insert_vt_log_file_path(vt_data)

            if result_value == 0:
                abort(404)
        # NEEDS TO TEST THIS AGAIN
        elif vt_resp == 0:
            print("No Virus Total Results")
            vt_data["md5"] = md5
            result_value = db_access.insert_vt_log_file_path(vt_data)
            if result_value == 0:
                abort(404)    


        # write the binary file out to the file path --> refer to the zip.py (password encrypted)
        if os.path.exists(dest_dir_path):
            print("path exists")
            # write out the original file
            with open(dest_file_path, "wb") as writer:
                writer.write(malware_file_binary)
            # write out the zipped file  
            pyminizip.compress(dest_file_path,f"{time}_{md5}",zip_file, ZIPPED_PASSWORD, COMPRESSION_LEVEL)
        else:
            # os.makedirs(dest_dir_path, exist_ok=True)
            os.mkdir(dest_dir_path)
            # write out the original file
            with open(dest_file_path, "wb") as writer:
                writer.write(malware_file_binary)
            # write out the zipped file  
            pyminizip.compress(dest_file_path,f"{time}_{md5}",zip_file, ZIPPED_PASSWORD, COMPRESSION_LEVEL)



    return jsonify({"data": True}), 201


"""
api route for storing general log
"""
@app.route('/api/v1/general_logs', methods=['POST'])
def insert_general_log():
    if request.json:
        general_log_data = request.json
        print("/api/v1/general_logs:")
        # print(general_log_data)
        result_value = db_access.insert_general_log(general_log_data)

        if result_value == 0:
            abort(404)

        return jsonify({"success": True}), 201

    else:
        abort(404)


"""
api route for storing nids log
"""
@app.route("/api/v1/snort_logs", methods=['POST'])
def insert_snort_log():
    if request.json:
        snort_log_data = request.json
        print("/api/v1/snort_logs:")
        # print(snort_log_data)
        result_value = db_access.insert_snort_log(snort_log_data)

        if result_value == 0:
            abort(404)

        return jsonify({"success": True}), 201

    else:
        abort(404)


"""
api route for storing session log
"""
@app.route("/api/v1/session_logs", methods=['POST'])
def insert_session_log():
    if request.json:
        session_log_data = request.json
        print("/api/v1/session_logs:")
        # print(session_log_data)
        result_value = db_access.insert_session_log(session_log_data)

        if result_value == 0:
            abort(404)

        return jsonify({"success": True}), 201

    else:
        abort(404)


"""
api route for retrieving the latest cowrie bruteforce log based on token
"""
@app.route("/api/v1/latest_bruteforce_log", methods=['POST'])
def retrieve_latest_bruteforce_log():
    print(f"/api/v1/latest_bruteforce_log:")
    if request.json:
        new_bruteforce_log = request.json
        all_session_logs = db_access.retrieve_all_session_logs()

        if all_session_logs:
            
            all_session_logs = json.loads(all_session_logs)
            bruteforce_logs = []

            for session_log in all_session_logs:
                # print(type(session_log['commands']))
                if (len(ast.literal_eval(session_log['credentials'])) > 0 and 
                    session_log['token'] == new_bruteforce_log['token'] and 
                    session_log['source_ip'] == new_bruteforce_log['peerIP'] and 
                    len(ast.literal_eval(session_log['commands'])) == 0 ):
                    bruteforce_logs.append(session_log)
                    
                    # print(f"Bruteforce log ==> \n {session_log}")

            # bruteforce_logs = [session_log for session_log in all_session_logs if (len(session_log['credentials']) > 0 and session_log['token'] == new_bruteforce_log['token'] and session_log['source_ip'] == new_bruteforce_log['peerIP'])]

            if len(bruteforce_logs) == 0:
                return jsonify({"bruteforce_log_empty": True}), 201
            else:
                return jsonify({"bruteforce_log_empty": False, "latest_bruteforce_log": json.dumps(bruteforce_logs[-1])}), 201

        else:
            return jsonify({"bruteforce_log_empty": True}), 201

    else:
        abort(404)


"""
api route for appending to the latest cowrie bruteforce log 
"""
@app.route("/api/v1/update_bruteforce_log", methods=['POST'])
def update_bruteforce_log():
    if request.json:
        bruteforce_log_data = request.json
        print("/api/v1/update_bruteforce_log:")
        result_value = db_access.update_bruteforce_log(bruteforce_log_data)
        # print(str(result_value) + " rows updated")
        if result_value == 0:
            abort(404)

        return jsonify({"success": True}), 201

    else:
        abort(404)


"""
api route for deleting general logs
"""
@app.route('/api/v1/general_logs', methods=['DELETE'])
def delete_general_log():
    if request.form['logData']:
        data = request.form['logData']
        data_list = data.split(',')
        print(type(data_list))
        print(data_list)
        result_value = db_access.delete_general_logs_by_id(data_list)

        if result_value == 0:
                abort(404)

        return jsonify({"rows_deleted": result_value}), 201

    else:
        abort(404)

"""
api route for deleting snort logs
"""
@app.route('/api/v1/snort_logs', methods=['DELETE'])
def delete_snort_log():
    if request.form['logData']:
        data = request.form['logData']
        data_list = data.split(',')
        print(type(data_list))
        print(data_list)
        result_value = db_access.delete_snort_logs_by_id(data_list)

        if result_value == 0:
                abort(404)

        return jsonify({"rows_deleted": result_value}), 201

    else:
        abort(404)


"""
api route for deleting session logs
"""
@app.route('/api/v1/session_logs', methods=['DELETE'])
def delete_session_log():
    if request.form['logData']:
        data = request.form['logData']
        data_list = data.split(',')
        print(type(data_list))
        print(data_list)
        result_value = db_access.delete_session_logs_by_id(data_list)

        if result_value == 0:
                abort(404)

        return jsonify({"rows_deleted": result_value}), 201
    
    else:
        abort(404)


"""
api route for deleting virus total logs
"""
@app.route('/api/v1/virus_total_logs', methods=['DELETE'])
def delete_virus_total_log():
    if request.form['logData']:
        data = request.form['logData']
        data_list = data.split(',')
        print(type(data_list))
        print(data_list)
        result_value = db_access.delete_vt_logs_by_id(data_list)

        if result_value == 0:
                abort(404)

        return jsonify({"rows_deleted": result_value}), 201
    
    else:
        abort(404)


"""
api route for data correlation - rule 1 - one attacker vs multiple honeynodes
"""
@app.route('/api/v1/data_correlation/rule_1/datatables', methods=['POST'])
def rule_1():
    date_time = request.form['datetimes'].split(" - ")
    """ Msg: Aaron Insert your db method here"""
    general_logs = db_access.retrieve_all_general_logs_date_range(date_time[0], date_time[1])
    if general_logs == {}:
        general_logs = []
    else:
        general_logs = json.loads(general_logs)
    
    nids_logs = db_access.retrieve_all_nids_logs_date_range(date_time[0], date_time[1])
    if nids_logs == {}:
        nids_logs = []
    else:
        nids_logs = json.loads(nids_logs)

    # general_logs = json.loads(db_access.retrieve_all_general_logs_date_range(date_time[0], date_time[1]))
    # nids_logs = json.loads(db_access.retrieve_all_nids_logs_date_range(date_time[0], date_time[1]))

    # general_logs = json.loads(db_access.retrieve_all_general_logs())
    # nids_logs = json.loads(db_access.retrieve_all_nids_logs())
    """----db ----"""
    correlator = DataCorrelator()
    dataset = correlator.get_dataset(general_logs,nids_logs)
    correlated_data = correlator.rule_1(dataset)
    # print(correlated_data)
    # correlated_data = []
    datatable_dict = dict()
    datatable_dict["data"] = correlated_data
    return datatable_dict

"""
api route for data correlation - rule 2 - one attacker vs one honeynode - attack multiple times, 5 nmap scans etc..
"""
@app.route('/api/v1/data_correlation/rule_2/datatables', methods=['POST'])
def rule_2():
    date_time = request.form['datetimes'].split(" - ")
    """ Msg: Aaron Insert your db method here"""""" Msg: Aaron Insert your db method here"""
    general_logs = db_access.retrieve_all_general_logs_date_range(date_time[0], date_time[1])
    if general_logs == {}:
        general_logs = []
    else:
        general_logs = json.loads(general_logs)
    
    nids_logs = db_access.retrieve_all_nids_logs_date_range(date_time[0], date_time[1])
    if nids_logs == {}:
        nids_logs = []
    else:
        nids_logs = json.loads(nids_logs)

    # general_logs = json.loads(db_access.retrieve_all_general_logs_date_range(date_time[0], date_time[0]))
    # nids_logs = json.loads(db_access.retrieve_all_nids_logs_date_range(date_time[0], date_time[0]))

    # general_logs = json.loads(db_access.retrieve_all_general_logs())
    # nids_logs = json.loads(db_access.retrieve_all_nids_logs())
    """----db ----"""
    correlator = DataCorrelator()
    dataset = correlator.get_dataset(general_logs,nids_logs)
    correlated_data = correlator.rule_2(dataset)
    # print(correlated_data)
    # correlated_data = []
    datatable_dict = dict()
    datatable_dict["data"] = correlated_data
    # print(datatable_dict)
    return datatable_dict

"""
api route for data correlation - rule 3 - multiple attackers vs one honeynode 
"""
@app.route('/api/v1/data_correlation/rule_3/datatables', methods=['POST'])
def rule_3():
    date_time = request.form['datetimes'].split(" - ")
    """ Msg: Aaron Insert your db method here"""
    general_logs = db_access.retrieve_all_general_logs_date_range(date_time[0], date_time[1])
    if general_logs == {}:
        general_logs = []
    else:
        general_logs = json.loads(general_logs)
    
    nids_logs = db_access.retrieve_all_nids_logs_date_range(date_time[0], date_time[1])
    if nids_logs == {}:
        nids_logs = []
    else:
        nids_logs = json.loads(nids_logs)

    # general_logs = json.loads(db_access.retrieve_all_general_logs_date_range(date_time[0], date_time[0]))
    # nids_logs = json.loads(db_access.retrieve_all_nids_logs_date_range(date_time[0], date_time[0]))

    # general_logs = json.loads(db_access.retrieve_all_general_logs())
    # nids_logs = json.loads(db_access.retrieve_all_nids_logs())
    """----db ----"""
    correlator = DataCorrelator()
    dataset = correlator.get_dataset(general_logs,nids_logs)
    correlated_data = correlator.rule_3(dataset)
    # print(correlated_data)
    # correlated_data = []
    datatable_dict = dict()
    datatable_dict["data"] = correlated_data
    # print(datatable_dict)
    return datatable_dict

"""
api route for number of attacks - rule 2 - one attacker vs one honeynode - attack multiple times, 5 nmap scans etc..
"""
@app.route('/api/v1/data_correlation/rule_2/num_of_attacks')
def num_of_attacks():
    """ Msg: Aaron insert your db method here --> hardcode the time window to 24 hours"""
    general_logs = db_access.retrieve_all_general_logs_last_24_hours()
    if general_logs == {}:
        general_logs = []
    else:
        general_logs = json.loads(general_logs)
    
    nids_logs = db_access.retrieve_all_nids_logs_last_24_hours()
    if nids_logs == {}:
        nids_logs = []
    else:
        nids_logs = json.loads(nids_logs)
    # general_logs = json.loads(db_access.retrieve_all_general_logs_last_24_hours())
    # nids_logs = json.loads(db_access.retrieve_all_nids_logs_last_24_hours())
    correlator = DataCorrelator()
    dataset = correlator.get_dataset(general_logs,nids_logs)
    correlated_data = correlator.rule_2(dataset)
    num_of_attacks = len(correlated_data)
    data = {
        'num_of_attacks':num_of_attacks
    }
    return data


if __name__ == "__main__":
    try:
        http_server = WSGIServer(('0.0.0.0', 5000), app)
        # run hpfeeds broker, this will also create the sqlite.db file in the current dir if it doesn't exist
        # hpfeeds_broker_process = subprocess.Popen(["hpfeeds-broker", "-e", "tcp:port=10000"], stdout=subprocess.PIPE, cwd=basedir)
        sleep(5)
        # log_collector_thread = Thread(target=log_collector.main, args=())
        app.debug = True
        # log_collector_thread.start()
        print('Waiting for requests.. ')
        http_server.serve_forever()
        

    except:
        # hpfeeds_broker_process.terminate()
        print("Exception")


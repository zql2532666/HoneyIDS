import yaml, json, requests
from DbAccess import *
from gevent.pywsgi import WSGIServer
from flask_mysqldb import MySQL
from flask import Flask, render_template, request, jsonify, abort, redirect, url_for, flash,send_file

app = Flask(__name__,
            static_url_path='', 
            static_folder='static',
            template_folder='templates')
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Configure DB
db = yaml.load(open('db.yaml'), Loader=yaml.SafeLoader)
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']

# Initialise Database
db_access = DbAccess(app)

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
        node_name = request.form['nodename']
        ip_addr = request.form['ipaddress']
        
        if(node_name and ip_addr):
            flash(u'Node successfully added.', 'success')
        else:
            flash(u'Node not added.', 'danger')
        
        # redirect to end the POST handling
        return redirect(url_for('nodes'))

    return render_template("addnode.html", title="Add Node")

@app.route("/log", methods=['GET', 'POST'])
def log():

    return render_template("log.html", title="Logs")

######################################## API CALLS ############################################
""" 
API Routes for HoneyNode Operations
Author: Aaron
"""

# Deactivate node
@app.route("/api/v1/deactivate/<string:token>", methods=['PUT'])
def deactivate_node(token):
    if token:

        ###### call heartbeat server ######

        return jsonify({'success': True}), 200
    else:
        return abort(404, "Token not specified")

    

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
    datatable_dict["data"] = json.loads(db_access.retrieve_all_nodes())

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
        abort(404)

    return jsonify({'success': True}), 200

""" 
API ROUTES FOR DEPLOYMENT SCRIPTS  
Author: Derek
"""
@app.route("/api/v1/deployment_script/cowrie", methods=['GET'])
def send_deployment_script_cowrie():
    return send_file("deployment_scripts/deploy_cowrie.sh")

@app.route("/api/v1/deployment_scripts/drupot", methods=['GET'])
def send_deployment_script_drupot():
    return send_file("deployment_scripts/deploy_drupot.sh")

@app.route("/api/v1/deployment_scripts/elastichoney", methods=['GET'])
def send_deployment_script_elastichoney():
    return send_file("deployment_scripts/deploy_elastichoney.sh")

@app.route("/api/v1/deployment_scripts/shockpot", methods=['GET'])
def send_deployment_script_shockpot():
    return send_file("deployment_scripts/deploy_shockpot.sh")

@app.route("/api/v1/deployment_scripts/snort", methods=['GET'])
def send_deployment_script_snort():
    return send_file("deployment_scripts/deploy_snort.sh")

@app.route("/api/v1/deployment_scripts/sticky_elephant", methods=['GET'])
def send_deployment_script_sticky_elephant():
    return send_file("deployment_scripts/deploy_sticky_elephant.sh")

@app.route("/api/v1/deployment_scripts/wordpot", methods=['GET'])
def send_deployment_script_wordpot():
    return send_file("deployment_scripts/deploy_wordpot.sh")




if __name__ == "__main__":
    try:
        http_server = WSGIServer(('0.0.0.0', 5000), app)
        app.debug = True
        print('Waiting for requests.. ')
        http_server.serve_forever()
    except:
        print("Exception")


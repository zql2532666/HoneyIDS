import yaml, json
from DbAccess import *
from gevent.pywsgi import WSGIServer
from flask_mysqldb import MySQL
from flask import Flask, render_template, request, jsonify, abort, redirect, url_for, flash

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

# Uncomment for testing
# @app.route("/test", methods=['GET', 'POST'])
# def test():
#     return render_template("test.html")

# CRUD endpoints
# Retrieve all honeynodes
@app.route("/api/v1/honeynodes/", methods=['GET'])
def retrieveAllNodes():

    return db_access.retrieve_all_nodes()

# Retrieve all honeynodes
@app.route("/api/v1/honeynodes/datatables", methods=['GET'])
def retrieve_all_nodes_for_datatables():

    datatable_dict = dict()
    datatable_dict["data"] = json.loads(db_access.retrieve_all_nodes())

    return datatable_dict

#Retrieve all honeynodes for heartbeat server
@app.route("/api/v1/heartbeats/", methods=['GET'])
def retrieveAllNodesForHeartbeat():

    return db_access.retrieve_all_nodes_for_heartbeat()

#Retrieve single honeynode
@app.route("/api/v1/honeynodes/<string:token>", methods=['GET'])
def retrieveNode(token):

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
def createNode():

    if not request.json or not 'token' in request.json:
        abort(400)

    resultValue = db_access.create_node(request.json)

    if resultValue == 0:
        abort(404)

    return jsonify({'success': True}), 201

# Update honeynode
@app.route("/api/v1/honeynodes/<string:token>", methods=['PUT'])
def updateNode(token):
    
    if not request.json or not token:
        abort(400)
    
    resultValue = db_access.update_node(request.json, token)

    if resultValue == 0:
        abort(404, "no values inserted")

    return jsonify({'success': True}), 200


# Delete honeynode
@app.route("/api/v1/honeynodes/<string:token>", methods=['DELETE'])
def deleteNode(token):

    if not token:
        abort(400)

    resultValue = db_access.delete_node(token)

    if resultValue == 0:
        abort(404)

    return jsonify({'success': True}), 200

if __name__ == "__main__":
    try:
        http_server = WSGIServer(('0.0.0.0', 5000), app)
        app.debug = True
        print('Waiting for requests.. ')
        http_server.serve_forever()
    except:
        print("Exception")


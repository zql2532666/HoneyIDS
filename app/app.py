import yaml, json
from DbAccess import *
from gevent.pywsgi import WSGIServer
from flask_mysqldb import MySQL
from flask import Flask, render_template, request, jsonify, abort

# TODO:
# //add in gevent
# //db connections


app = Flask(__name__,
            static_url_path='', 
            static_folder='static',
            template_folder='templates')

# Configure DB
db = yaml.load(open('db.yaml'), Loader=yaml.SafeLoader)
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']

mysql = MySQL(app)

@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error=str(e)), 404

@app.route("/")
@app.route("/index.html")
def index():
    return render_template("index.html")

@app.route("/index2.html")
def index2():
    return render_template("index2.html")

@app.route("/index3.html")
def index3():
    return render_template("index3.html")

@app.route("/deploy", methods=['GET', 'POST'])
def deploy():
    return render_template("deploy.html")

# CRUD endpoints
# Retrieve all honeynodes
@app.route("/api/v1/honeynodes/", methods=['GET'])
def retrieveAllNodes():

    json_data = {}

    #Mysql connection
    cur = mysql.connection.cursor()

    sql = "select * from nodes"
    resultValue = cur.execute(sql)
    if resultValue > 0:
        my_query = DbAccess.query_db(cur)
        json_data = json.dumps(my_query, default=DbAccess.myconverter)

    return str(json_data)

#Retrieve single honeynode
@app.route("/api/v1/honeynodes/<string:token>", methods=['GET'])
def retrieveNode(token):

    json_data = {}

    #Mysql connection
    cur = mysql.connection.cursor()

    sql = f"select * from nodes where token={token}"
    resultValue = cur.execute(sql)
    if resultValue > 0:
        my_query = DbAccess.query_db(cur)
        json_data = json.dumps(my_query, default=DbAccess.myconverter)

    return str(json_data)

# Create honeynode
@app.route("/api/v1/honeynodes/", methods=['POST'])
def createNode():

    if not request.json or not 'token' in request.json:
        abort(400)

    #Mysql connection
    cur = mysql.connection.cursor()

    honeynode_name = request.json['honeynode_name']
    ip_addr = request.json['ip_addr']
    subnet_mask = request.json['subnet_mask']
    honeypot_type = request.json['honeypot_type']
    nids_type = request.json['nids_type']
    no_of_attacks = request.json['no_of_attacks']
    date_deployed = request.json['date_deployed']
    heartbeat_status = request.json['heartbeat_status']
    token = request.json['token']

    sql = f"insert into nodes(honeynode_name, ip_addr, subnet_mask, honeypot_type, nids_type, no_of_attacks, date_deployed, heartbeat_status, token) \
        values('%s', '%s', '%s', '%s', '%s', %d, '%s', '%s', '%s')" % (honeynode_name, ip_addr, subnet_mask, honeypot_type, nids_type, int(no_of_attacks), date_deployed, heartbeat_status, token)
    
    resultValue = 0

    try:
        resultValue = cur.execute(sql)
        mysql.connection.commit()
        cur.close()
    except Exception as err:
        print(err)

    if resultValue == 0:
        abort(404)

    return jsonify({'success': True}), 201

# Update honeynode
@app.route("/api/v1/honeynodes/<string:token>", methods=['PUT'])
def updateNode(token):

    if not request.json or not 'token' in request.json:
        abort(400)

    #Mysql connection
    cur = mysql.connection.cursor()

    honeynode_name = request.json['honeynode_name']
    ip_addr = request.json['ip_addr']
    subnet_mask = request.json['subnet_mask']
    honeypot_type = request.json['honeypot_type']
    nids_type = request.json['nids_type']
    no_of_attacks = request.json['no_of_attacks']
    date_deployed = request.json['date_deployed']
    heartbeat_status = request.json['heartbeat_status']
    token = request.json['token']

    sql = "update nodes set honeynode_name='%s', ip_addr='%s', subnet_mask='%s', honeypot_type='%s', \
        nids_type='%s', no_of_attacks=%d, date_deployed='%s', heartbeat_status='%s' where token='%s'" \
            % (honeynode_name, ip_addr, subnet_mask, honeypot_type, nids_type, int(no_of_attacks), date_deployed, heartbeat_status, token)
    
    resultValue = 0

    try:
        resultValue = cur.execute(sql)
        mysql.connection.commit()
        cur.close()
    except Exception as err:
        print(err)

    if resultValue == 0:
        abort(404)

    return jsonify({'success': True}), 200


# Delete honeynode
@app.route("/api/v1/honeynodes/<string:token>", methods=['DELETE'])
def deleteNode(token):

    if not token:
        abort(400)

    #Mysql connection
    cur = mysql.connection.cursor()

    sql = f"delete from nodes where token='{token}'"
    
    resultValue = 0

    try:
        resultValue = cur.execute(sql)
        mysql.connection.commit()
        cur.close()
    except Exception as err:
        print(err)

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
    # app.run(host="0.0.0.0", debug = True)


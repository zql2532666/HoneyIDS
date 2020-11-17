import yaml, json
from DbAccess import *
from gevent.pywsgi import WSGIServer
from flask_mysqldb import MySQL
from flask import Flask, render_template, request

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

@app.route("/deploy.html")
def deploy():
    return render_template("deploy.html")

#Sample route for CRUD. Might change
@app.route("/retrieveNodes", methods=['GET'],)
def retrieveNodes():
    
    json_data = {}

    #Mysql connection
    cur = mysql.connection.cursor()

    sql = "select * from nodes"
    resultValue = cur.execute(sql)
    if resultValue > 0:
        my_query = DbAccess.query_db(cur)
        json_data = json.dumps(my_query, default=DbAccess.myconverter)

    return str(json_data)

@app.route("/updateNode", methods=['POST'])
def updateNode():
    token = request.get_data
    return token

# @app.route("/updateNode")
# def update():
#     return "updated"

# @app.route("/deleteNode")
# def delete():
#     return "deleted"

if __name__ == "__main__":
    try:
        http_server = WSGIServer(('0.0.0.0', 5000), app)
        app.debug = True
        print('Waiting for requests.. ')
        http_server.serve_forever()
    except:
        print("Exception")
    # app.run(host="0.0.0.0", debug = True)


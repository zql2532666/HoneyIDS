from flask import Flask, render_template

# TODO:
# add in gevent
# db connections


app = Flask(__name__,
            static_url_path='', 
            static_folder='static',
            template_folder='templates')

@app.route("/")
def index():
    return render_template("index.html")

#Sample route for CRUD. Might change
@app.route("/addNode")
def add():
    return "added"

@app.route("/getNode")
def get():
    return "get"

@app.route("/updateNode")
def update():
    return "updated"

@app.route("/deleteNode")
def delete():
    return "deleted"

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug = True)


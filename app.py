from flask import Flask, render_template, request
from pymongo import MongoClient
import os, logging, json, secrets

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth', methods=['POST'])
def auth():
    login = json.loads( request.get_data().decode("utf-8") )
    log.info( "POST at /auth data: " + str(login) )
    # SUPER UNSAFE way to add the username and password to the MongoDB database
    result = db.users.insert_one( login )
    if result != None: return str(result)
    else: return "Auth Fail"

logging.basicConfig(level=os.environ.get("LOGLEVEL","INFO"))
log = logging.getLogger(__file__)
log.info("Starting web server")

log.info("Connecting to MongoDB")
# Connects to the MongoDB container running with user "root" and password "test123"
client = MongoClient('mongodb://root:test123@mongodb:27017')
# Creates the webauth database in MongoDB
db = client.webauth

app.run('0.0.0.0', 8080, debug=True)

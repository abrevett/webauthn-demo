from flask import Flask, render_template, request
from pymongo import MongoClient
import os, logging, json, secrets

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# This route registers a new user
@app.route('/api/register', methods=['GET','POST'])
def auth():
    if request.method == 'POST':
        # Casting POST data to a Python dict
        login = json.loads( request.get_data().decode("utf-8") )
        log.info( "POST at /auth data: " + str(login) )
        # Check db if the user alredy exists
        if db.users.count_documents( {"username":login['username']} ) > 0:
            return "User already exists"
        # SUPER UNSAFE way to add the username and password to the MongoDB database
        result = db.users.insert_one( login )
        if result != None: return str(result)
        else: return "Auth Fail"

# This route authenticates an existing user
@app.route('/api/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        verify = json.loads( request.get_data().decode("utf-8") )
        log.info( "POST at /api/login: " + str(login) )
        # Check db for the user existing
        if db.users.count_documents( {"username":verify['username']} ) < 0:
            return "User doesn't exist"
        return "Auth OK"

logging.basicConfig(level=os.environ.get("LOGLEVEL","INFO"))
log = logging.getLogger("webauthn")
log.info("Starting web server")

log.info("Connecting to MongoDB")
# Connects to the MongoDB container running with user "root" and password "test123"
client = MongoClient('mongodb://root:test123@mongodb:27017')
# Creates the webauth database in MongoDB
db = client.webauth

app.run('0.0.0.0', 8080, debug=True)

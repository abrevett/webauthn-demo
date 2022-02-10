from flask import Flask, render_template, request
from pymongo import MongoClient
import webauthn
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential
from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse
import os, logging, json, secrets

app = Flask(__name__)

# These are hardcoded but should be dynamically configured with files
ORIGIN="http://webauthn.sandbox"
RELAY_PARTY="webauthn.sandbox"
COMPANY="WebAuthn Example, LLC"

@app.route('/')
def index():
    return render_template('index.html')

# This route registers a new user
@app.route('/api/register', methods=['GET','POST'])
def auth():
    payload = json.loads( request.get_data().decode("utf-8") )
    # If I GET to here, check if the username is taken, and then send Credential Options
    if request.method == "GET":
        # Making sure the username and email aren't already taken
        if db.users.count_documents( {"email": payload['email']} ) > 0:
            return { "error":"Email already exists. Login Instead." }
        if db.users.count_documents( {"username": payload['username']} ) > 0:
            return { "error":"Username is already taken" }
        # We are going to use the DB-generated ID as the user ID, but should be something different
        userid = db.users.insert_one( {"email": payload['email'], "username": payload['username']} ).inserted_id
        # We generate simple registration options because this is just a demo
        cred_opts = webauthn.simple_registration_options(
                rp_id=RELAY_PARTY, # Make sure this is the domain in the browser. Im using webauthn.sandbox
                rp_name=COMPANY,
                user_id=userid,
                user_name=payload['email'],
                user_display_name=payload['username']
        )
        # We also need to temporarily store the generated challenge
        db.users.update_one( {"_id": userid}, {"challenge": base64.urlsafe_b64encode(cred_opts.challenge)} )
        # Finally, we send off the credential as a JSON object, using the WebAuthn helper
        return { "publicKey": json.loads(webauthn.options_to_json(cred_opts)) }
    # If I POST to here, verify that the data returned is valid
    if request.method == "POST":
        # We get the database ID and ensure it is the right user
        userid = base64.urlsafe_b64decode(payload['id']).decode("utf-8")
        user_rec = db.users.find_one( {"_id": userid} )
        if user_rec == None:
            return { "error": "Account not found" }
        if user_rec['email'] != payload['email'] or user_rec['username'] != payload['username'] or user_rec['publicKey'] != None:
            return { "error": "Incorrect email-username pair" }
        # We now validate the registration object itself using the WebAuthn helpers
        try:
            valid_obj = webauthn.verify_registration_response(
                credential = RegistrationCredential.parse_raw( json.dumps(payload['credential']) ),
                expected_challenge = webauthn.base64url_to_bytes(
                    webauthn.base64url_to_bytes( db.users.find_one( {"_id": userid} )['challenge'] )
                ),
                expected_origin=ORIGIN,
                expected_rp_id=RELAY_PARTY
            )
        except InvalidRegistrationResponse:
            # We need to clean up the User table of our previous insertion and return an error
            return { "error": "Registration Failed" }
        else:
            # If we get a good validation object, we insert the public key and set the sign in count to 0
            err = db.users.update_one({"_id": userid}, {'$set':{ 
                'credentials': {
                    'publicKey': valid_obj.credential_public_key,
                    'sign_in': 0
                }}})
            return { "info": "Registration successful" }
        #### OLD CODE ####
        # Casting POST data to a Python dict
        #login = json.loads( request.get_data().decode("utf-8") )
        #log.info( "POST at /auth data: " + str(login) )
        # Check db if the user alredy exists
        #if db.users.count_documents( {"username":login['username']} ) > 0:
        #    return "User already exists"
        # SUPER UNSAFE way to add the username and password to the MongoDB database
        #result = db.users.insert_one( login )
        #if result != None: return str(result)
        #else: return { "error":"Auth Fail" }
    return { "error":"Incorrect REST API method" }

# This route authenticates an existing user
@app.route('/api/login', methods=['GET','POST'])
def login():
    payload = json.loads( request.get_data().decode("utf-8") )
    # If I GET to here, check that the username exists, and then send Credential challenge
    if request.method == 'GET':
        # We first make sure that the email given has an account
        if db.users.count_documents( {"email": payload['email']} ) <= 0:
            return { "error":"Email invalid" }
        # We send a simple authentication response to challenge the suspected user
        auth_chal = webauthn.generate_authentication_options(rp_id="webauthn.sandbox")
        # This should be safe, as we will only ever have one user at a time
        db.users.update_one({"email": payload['email']}, {'$set':{
            "challenge": base64.urlsafe_b64encode(auth_chal.challenge)
        }})
        # Finally, we send off the credential as a JSON object, using the WebAuthn helper
        return { "publicKey": json.loads(webauthn.options_to_json(auth_chal)) }
    # If I POST to here, verify that the signature is valid and test against stored credential
    if request.method == 'POST':
        # We get the email and try to verify that the given credential is correct
        user = db.users.find_one( {"email": payload['email']} )
        try:
            auth_verify = webauthn.verify_authentication_response(
                credential=AuthenticationCredential.parse_raw( json.dumps(payload['credential']) ),
                expected_challenge=base64url_to_bytes( user['challenge'] ),
                expected_origin=ORIGIN,
                expected_rp_id=RELAY_PARTY,
                credential_public_key=base64url_to_bytes( user['credentials']['publicKey'] ),
                credential_current_sign_count=user['credentials']['sign_in']
            )
        except InvalidAuthenticationResponse:
            # We simply print error and get rid of challenge
            return { "error":"Login Failed" }
        else:
            # We erase the challenge and increment the sign in count
            db.users.update_one( {"_id": user["_id"]}, {
                '$set':{
                    "challenge":""
                },
                '$inc':{
                    "credentials":{ "sign_in": 1 }
                }
            })
            # We must ensure that the sign-in attempt in the database and the one in this thread is the same
            user = db.users.find_one( {"email": payload['email']} )
            try:
                assert user['credentials']['sign_in']==auth_verify.new_sign_count
            except:
                return { "error":"Replay attack detected" }
            else:
                return { "info":"Auth OK" }
            return { "error": "Unkown error encountered" }
        #### OLD CODE ####
        #verify = json.loads( request.get_data().decode("utf-8") )
        #log.info( "POST at /api/login: " + str(login) )
        # Check db for the user existing
        #if db.users.count_documents( {"username":verify['username']} ) < 0:
        #    return "User doesn't exist"
        #return "Auth OK"
    return { "error":"Incorrect REST API method" }

logging.basicConfig(level=os.environ.get("LOGLEVEL","INFO"))
log = logging.getLogger("webauthn")
log.info("Starting web server")

log.info("Connecting to MongoDB")
# Connects to the MongoDB container running with user "root" and password "test123"
client = MongoClient('mongodb://root:test123@mongodb:27017')
# Creates the webauth database in MongoDB
db = client.webauth

app.run('0.0.0.0', 8080, debug=True)

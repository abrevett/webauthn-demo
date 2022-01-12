# WebAuthn Demo
This is a small demo for a simple WebAuthn authentication to a web server. This project uses Flask for the server and the [python webauthn module by Duo Labs](https://github.com/duo-labs/py_webauthn), with credentials stored by MongoDB.

Requires docker, docker-compose to run.

## Basic Development Instructions

 1. First, ensure you have Docker and docker-compose downloaded on your machine: `docker -v; docker-compose -v`
 2. Get MongoDB from DockerHub: `docker pull mongo:5-focal`. Do not change the version for now
 3. Build the image: `docker build -t abrevett/webauthn-demo .`
 4. Compose the containers: `docker-compose up`
 5. When finished testing, hit `CTRL+C` to exit,  then type `docker-compose down`
 6. After making  changes, test them by repeating from step 3

**Important Notes**
- The MongoDB server will save its database in the db directory, and the BLANK file is there to ensure git keeps track of the directory. Ensure that NO data from MongoDB gets committed to this repo.
- docker-compose sets up DNS for the containers, so that the MongoClient URL `mongodb://root:test123@mongodb:27017` resolves to the MongoDB container.

If there are any questions, email me at abrevett@udel.edu

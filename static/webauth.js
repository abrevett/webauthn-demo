/**
 * Registers a new user on the website
 *
 * Goes to the TPM and fetches a public key to 
 * give to the server to register
 *
 * To guarantee that all data is sent and is valid, this is a Promise chain
*/
var registerUser = function(){
	var email = document.querySelector("#register-email").value;
	var user = document.querySelector("#register-user").value;
	var resp = null;
	// Sending our email and username to check if the user is taken
	fetch('/api/register', {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify( {email: email, username: user} )
	}).then(r=>r.json())
		.then(resp => {
			if('error' in resp){ console.log(resp);	return;	}
			if( !('publicKey' in resp) ){ console.log(resp); return; }
	// We must take the response object and properly cast its datatypes
	// to ArrayBuffer types
	var id = resp.publicKey.user.id;
	resp.publicKey.challenge = bufferDecode( resp.publicKey.challenge );
	resp.publicKey.challenge = bufferDecode( resp.publicKey.user.id );
	if(resp.publicKey.excludeCredentials) {
		for(var i=0; i<resp.publicKey.excludeCredentials.length; i++){
			resp.publicKey.excludeCredentials[i].id = bufferDecode( resp.publicKey.excludeCredentials[i].id );
		}
	}
	// We directly use the response object from the api to send to the
	// web browser, which will make a key pair on the TPM
	navigator.credentials.create({
		publicKey: resp.publicKey
	}).then( cred => {
		// We take the Array Objects of the Credential object and turn them
		// into URL-safe Base64 to compress size
		cred.rawId = bufferEncode( cred.rawId );
		cred.response.attestationObject = bufferEncode( cred.response.attestationObject );
		cred.response.clientDataJSON = bufferEncode( cred.response.clientDataJSON );
	// Finally, we send the credentials from the TPM back to the server
	// to finish the registration process
	fetch('/api/register', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify( {email: email, username: user, id: id, credential: cred} )
	}).then(r=>r.json())
		.then(resp => { 
			// Now to just print the response just for fun
			document.querySelector("#auth-ok").innerText = resp; 
	// Catching the error from api/register POST
		}).catch(err => { console.log(err); });
	// Catching the error from navigator.credentials.create
	}).catch( function(err) {
		console.info(err);
		});
	// Catching the error from api/register PUT
	}).catch(err => { console.log(err); 
	});
};

/**
 * Authenticates to the website
 *
 * Takes the challenge from the server and 
 * forwards it to the TPM, then sends the 
 * result back to the server to authenticate.
*/
var loginUser = function(){
	var email = document.querySelector("#login-email").value;
	// We send our email to verify an account exists and
	// get the server challenge
	fetch('/api/login', {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify( {email: email} )
	}).then(r=>r.json())
		.then(dat => { resp = dat; })
		.catch(err => { console.log(err); });
	if(resp.error !== undefined){
		console.log(resp.error);
		return;
	}

	// We take our response Object and ensure the correct datatypes
	resp.publicKey.challenge = bufferDecode( resp.publicKey.challenge );
	resp.publicKey.allowCredentials.forEach( function(creditem) {
		creditem.id = bufferDecode( creditem.id );
	});

	// We send our object to the TPM to get a coded response
	var cred = null
	navigator.credentials.get({
		publicKey: resp.publicKey
	}).then( function(new_cred) {
		cred = new_cred;
	}).catch( function(err) {
		console.info(err);
	});

	// We again change the data format for sending to the server
	cred.rawId = bufferEncode( cred.rawId );
	cred.response.authenticatorData = bufferEncode( cred.response.authenticatorData );
	cred.response.clientDataJSON = bufferEncode( cred.response.clientDataJSON );
	cred.response.signature = bufferEncode( cred.response.signature );
	cred.response.userHandle = bufferEncode( cred.response.userHandle );

	// And give it to the server to verify our credentials
	resp = null;
	fetch('/api/register', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify( {email: email, credential: cred} )
	}).then(r=>r.json())
		.then(dat => { resp = dat; })
		.catch(err => { console.log(err); });
	if(resp.error !== undefined){
		console.log(resp.error);
		return;
	}

	// Again we display the response from the server
	document.querySelector("#auth-ok").innerText = resp;
};


/********************
 * HELPER FUNCTIONS *
 ********************/
function bufferDecode(b64str){
	return Uint8Array.from( atob(b64str), c => c.charCodeAt(0) );
}

function bufferEncode(buffer){
	return window.btoa(String.fromCharCode.apply(null, buffer))
		.replace("/\+/g", "-")
		.replace("/\//g", "_")
		.replace("/=/g", "");
}

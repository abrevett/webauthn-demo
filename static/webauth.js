var sendForm = function(){
	var user = document.querySelector("#user").value;
	var pass = document.querySelector("#pass").value;
	var ajaxreq = new XMLHttpRequest();
	ajaxreq.onreadystatechange = function(){
		document.querySelector("#authok").innerText = this.responseText;
	};
	ajaxreq.open('POST', 'api/register', true);
	ajaxreq.send(JSON.stringify({
		username: user,
		password: pass
	}));
};

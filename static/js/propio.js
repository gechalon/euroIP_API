	
function ValidateIPaddress(inputText)
 {
	 var ipformat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
	 if(inputText.value.match(ipformat))
	 {
		 inputText.focus();
		 return true;
	 }
	 else
	 {
		 alert("You have entered an invalid IP address!");
		 inputText.focus();
		 return false;
	 }
 }
 
 function redirigir(destino)
 {
	 window.location.replace =destino;	 
 }
 
 
 
var inactivityTimeout = 300000; // 5 minutos de inactividad
var logoutTimer = setTimeout(logout, inactivityTimeout);

function resetTimer() {
  clearTimeout(logoutTimer);
  logoutTimer = setTimeout(logout, inactivityTimeout);
}

function deleteCookie(name) {   
    document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';  
}  

function logout() {
	//alert("cookie : "+document.cookie);	
	if(document.cookie.includes('access_token_cookie'))//si tenemos access_token_cookie entre las cookies ->  hay sesion abierta
		  {
			resetTimer();  
			deleteCookie('access_token_cookie');
			window.location.href = "/logout"; // Redirige a la página de logout en Python
		  } 	
}


document.addEventListener("mousemove", resetTimer);
document.addEventListener("keypress", resetTimer);


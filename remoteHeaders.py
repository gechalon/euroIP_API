from flask import request
from ua_parser import user_agent_parser
import json
#-----la parte de cliente-------

def json_validator(data):
    try:
        json.loads(data)
        return True
    except ValueError as error:
        print("invalid json: %s" % error)
        return False
        
        
def get_ip_cliente(ip, allheaders):
    es_proxy=False
    proxy_data ='no_proxy'
    if 'X-Forwarded-For' in allheaders:
        proxy_data = allheaders['X-Forwarded-For']
        ip_list = proxy_data.split(',')
        user_ip = ip_list[0]  # first address in list is User IP
        es_proxy=True
    else:
        #De esta request, podemos extraer varios elementos - y la dirección IP se denota como la propiedad remote_addr
        #user_ip = request.remote_addr
        
        #REMOTE_ADDR es una de las variables (claves) del servidor que se asigna a la dirección IP del cliente o del servidor.  
        #user_ip = request.environ['REMOTE_ADDR'] 
        
        #get() para que, si no se establece la cabecera, podamos utilizar por defecto la dirección remota
        user_ip =request.environ.get('HTTP_X_REAL_IP', allheaders)
    
    return user_ip, es_proxy, proxy_data  
    

def get_user_agent(allheaders): 
    #print(request.headers['USER_AGENT'])
    if json_validator(allheaders) :
        parsed_agent = user_agent_parser.Parse(allheaders)    
    return  parsed_agent
    
    
def get_allHeaders(allheaders):
    headers={}
    if json_validator(allheaders) :
        headers=json.loads(allheaders)
    return headers
#-----FIN la parte de cliente------- 
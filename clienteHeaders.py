from flask import request
from ua_parser import user_agent_parser
#-----la parte de cliente-------

def get_ip_cliente():
    es_proxy=False
    proxy_data ='no_proxy'
    if 'X-Forwarded-For' in request.headers:
        proxy_data = request.headers['X-Forwarded-For']
        ip_list = proxy_data.split(',')
        user_ip = ip_list[0]  # first address in list is User IP
        es_proxy=True
    else:
        #De esta request, podemos extraer varios elementos - y la dirección IP se denota como la propiedad remote_addr
        #user_ip = request.remote_addr
        
        #REMOTE_ADDR es una de las variables (claves) del servidor que se asigna a la dirección IP del cliente o del servidor.  
        #user_ip = request.environ['REMOTE_ADDR'] 
        
        #get() para que, si no se establece la cabecera, podamos utilizar por defecto la dirección remota
        user_ip =request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    
    return user_ip, es_proxy, proxy_data  
    

def get_user_agent(): 
    #print(request.headers['USER_AGENT'])
    parsed_agent = user_agent_parser.Parse(str(request.user_agent))    
    return  parsed_agent
    
    
def get_allHeaders():
    headers_dict={}
    headers_dict=request.headers
    return headers_dict
#-----FIN la parte de cliente------- 
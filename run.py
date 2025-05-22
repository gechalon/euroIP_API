from flask import Flask 
from flask import render_template, flash, redirect, session, url_for
from flask import jsonify
from itertools import islice
from decouple import config as config_decouple


import clienteHeaders
import remoteHeaders
import ipjuis
import geoIPdata
import fuzzyGeoLoc
import security
import usage
import models
#import server
import configuracion
import webhooks

import mmap
import json
import datetime
import uuid, os
import stripe
from flask_mail import Mail

from email.message import EmailMessage
from smtplib import SMTP

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    #jwt_refresh_token_required,
    get_jwt,
    create_refresh_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies
)
from flask import make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.attributes import flag_modified
from flask_migrate import Migrate
from flask import request
# importar el modelo de User desde el archivo models.py
from models import User
from models import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta


from configuracion import logger
#app = Flask(__name__)

TEMPLATE_DIR = os.path.abspath('templates')
STATIC_DIR = os.path.abspath('static')

def create_app(enviroment):
    app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

    app.config.from_object(enviroment)

    with app.app_context():# inicializa la base de datos
        db.init_app(app)
        db.create_all()

    return app

logger.info("flask_env : ",os.environ.get('FLASK_ENV'))

enviroment = configuracion.config['development']#en principio, supongo entorno desarrollo
configuracion.enviroment = configuracion.config['development']

if config_decouple('PRODUCTION', default=False, cast=bool) and os.environ.get('FLASK_ENV', 'production'):#si existe la variable de entorno PRODUCTION y es True
    enviroment = configuracion.config['production']
    configuracion.enviroment = configuracion.config['production']

if os.environ.get('CLOUDSERVER', False)==True or config_decouple('CLOUDSERVER', default=False, cast=bool):#si existe la variable de entorno CLOUDSERVER y es True
    enviroment = configuracion.config['cloudserver']
    configuracion.enviroment = configuracion.config['cloudserver']

logger.info("enviroment en run: "+ str(enviroment))

app = create_app(enviroment)

#app.run(host='127.0.0.1', port=5000, debug=True)#desarrollo
#app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=False)#produccion#app.run(host='0.0.0.0', port=4004, debug=False)#produccion

app.config['SESSION_PERMANENT'] = True
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

app.config['MAIL_SERVER']='smtp.gmail.com'
#app.config['MAIL_PORT'] = 587
app.config['MAIL_PORT'] = 465
app.config['MAIL_NAME'] = 'privacy4IP'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] =  os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_CHARSET'] = 'utf-8'
app.config['MAIL_ASCII_ATTACHMENTS'] = False
mail = Mail(app)

app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)
migrate = Migrate(app, db)


 #=====================================================================================================================================================
# inicializa la base de datos
with app.app_context():
    db.create_all()

jwt = JWTManager(app)
#app.config['JWT_TOKEN_LOCATION'] = ['query_string']
csrf = CSRFProtect()
csrf.init_app(app)


 

@app.route("/", methods=['GET','POST'])

def index():        
    
    #--obtener ip de cliente---
    ip_address,es_proxy, proxy_list=clienteHeaders.get_ip_cliente()
    ipDetails={}
    #si se ha introducido una IP diferente en el formulario
    if request.method == 'POST':  
      ip_address = security.validate_ip_address(str(request.form['tryit_ip']).strip())
      # check if bogon.
      if not ip_address or ip_address==None :        
         #ipDetails["ip"] = ip_address
         ipDetails["valid"] = False
         return render_template("index.html",ipDetails=ipDetails)   
      if ip_address and security.is_bogon(ip_address):
         ipDetails["ip"] = ip_address
         ipDetails["bogon"] = True
         return render_template("index.html",ipDetails=ipDetails) 
    #--obtener agente de cliente---
    user_agent=clienteHeaders.get_user_agent()    
    #--obtener toda la cabecera http---
    headers_dict=clienteHeaders.get_allHeaders()
    headers=request.headers.to_wsgi_list()    
    #---esta usando TOR?--
    is_using_tor=security.using_tor(ip_address)
    
    #--obtener ipinfo de libreria ipwhois
    # #--obtener ipinfo de bd geoIP---	
    if ip_address=="127.0.0.1" or security.is_bogon(ip_address):# check if bogon ip.
        ipinfo_ipwhois=ipjuis.performWhoIs('85.85.40.166')
        ipinfo_bdGeoIP=geoIPdata.performGeoData('85.85.40.166')
    else:    
        ipinfo_ipwhois=ipjuis.performWhoIs(str(ip_address))
        ipinfo_bdGeoIP=geoIPdata.performGeoData(str(ip_address))
        
    #--obtener fuzzyGeolocalizacion a partir de datos anteriores---
    postal=ipinfo_bdGeoIP['postal_code']
    pais=ipinfo_bdGeoIP['country_code'] 
    aproxZone_json=fuzzyGeoLoc.obtener_aproxZone(postal, pais)# obtener aproxZone_json a partir de postal_code y country_code

    lat_pto_Ciudad=ipinfo_bdGeoIP['latitude']
    lon_pto_Ciudad=ipinfo_bdGeoIP['longitude']
    if aproxZone_json and  aproxZone_json!=[]  :
        lat_pto_Exacto=float(aproxZone_json[0]['lat'])
        lon_pto_Exacto=float(aproxZone_json[0]['lon'])
        #print(aproxZone_json)
    else: #hay zonas donde no se puede obtener aproxZone_json
        aproxZone_json=[]
        lat_pto_Exacto=lat_pto_Ciudad
        lon_pto_Exacto=lon_pto_Ciudad
    
    fuzzy_geoloc_lat, fuzzy_geoloc_lon, radius=fuzzyGeoLoc.get_fuzzy_ptomedio(lat_pto_Exacto,lon_pto_Exacto,lat_pto_Ciudad,lon_pto_Ciudad)
    fuzzy_circle=dict(fuzzy_geoloc_lat=fuzzy_geoloc_lat, fuzzy_geoloc_lon=fuzzy_geoloc_lon, radius=radius)
       
    #subnets_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'bbdd/listas/firehol_level1.netset') 
    #subnets_file = configuracion.ruta_level1
    subnets_file = os.path.join(configuracion.listas_PATH, 'firehol_level1.netset')
    proxies_file = os.path.join(configuracion.listas_PATH, 'firehol_proxies.netset')
    print("subnets_file : ",subnets_file)
    print("proxies_file : ",proxies_file)

    #import time

    resp, subred = security.search_ip_in_subnets(ip_address, subnets_file)
    #with open(proxies_file) as archivo:
        #esProxy1 = security.buscar_ip_recursiva(archivo, ip_address)
    
    #inicio1 = time.time()   
   
    with open(proxies_file, 'r') as archivo:  
       # Mapea el archivo a la memoria
        mm = mmap.mmap(archivo.fileno(), 0, access=mmap.ACCESS_READ)
    # Llama a la función buscar_ip_binaria con la IP buscada
        esProxy1 = security.buscar_ip_binaria(mm, ip_address, inicio=34)       
    #esProxy1 = security.buscar_ip_recursiva(proxies_file, ip_address)

    #fin1 = time.time()
    #print(f"La función proxies_file se ejecutó en {fin1 - inicio1} segundos")
    

    #return render_template("index.html", ip_address=ip_address, es_proxy=es_proxy, user_agent=user_agent, headers_dict=headers_dict, #ipinfo_ipwhois=ipinfo_ipwhois,ipinfo_bdGeoIP=ipinfo_bdGeoIP, fuzzy_geoloc_lat=fuzzy_geoloc_lat, fuzzy_geoloc_lon=fuzzy_geoloc_lon, radius=radius, #aproxZone_json=aproxZone_json[0]['boundingbox'],is_using_tor=is_using_tor)
    ipDetails["ip"] = ip_address
    ipDetails["es_proxy"] = es_proxy
    ipDetails["user_agent"] = user_agent
    ipDetails["headers_dict"] = headers_dict
    ipDetails["ipinfo_ipwhois"] = ipinfo_ipwhois
    ipDetails["ipinfo_bdGeoIP"] = ipinfo_bdGeoIP
    ipDetails["lat_pto_Exacto"] = lat_pto_Exacto
    ipDetails["lon_pto_Exacto"] = lon_pto_Exacto
    ipDetails["is_using_tor"] = is_using_tor
    ipDetails["aproxZone_json"] = aproxZone_json
    ipDetails["fuzzy_circle"] = fuzzy_circle    
    ipDetails["threats_list"] = resp
    ipDetails["subnet"] = subred
    ipDetails["proxies_list"] = esProxy1
    

    '''return render_template("index.html", ip_address=ip_address, es_proxy=es_proxy, user_agent=user_agent, headers_dict=headers_dict, ipinfo_ipwhois=ipinfo_ipwhois, ipinfo_bdGeoIP=ipinfo_bdGeoIP, lat_pto_Exacto=lat_pto_Exacto, lon_pto_Exacto=lon_pto_Exacto,is_using_tor=is_using_tor, aproxZone_json=aproxZone_json, fuzzy_circle=fuzzy_circle)'''
    return render_template("index.html",ipDetails=ipDetails) 

 
 #=====================================================================================================================================================
    
@app.route("/security/<string:ip_cliente>", methods=['GET'])
@jwt_required()

def security_info(ip_cliente):
    
    ipDetails={}
    try:
        token_arg = request.args.get('jwt')
        logger.info("token_arg (security): ",token_arg)
        bogonip=False
          # check if valid ip.
        if security.validate_ip_address(ip_cliente)==None:       
             return jsonify({"message": "IP NOT valid", "ip_address": str(ip_cliente)}), 401   
        if security.is_bogon(ip_cliente):# check if bogon ip.
             bogonip=True 
         #    return jsonify({"message": "Bogon IP", "ip_address": str(ip_cliente)}), 401
         
        # Obtengo el usuario correspondiente al token en bbdd
        user = User.query.filter_by(token=token_arg).first()
        if user and user.userprofile=="security":#cliente tiene perfil security
            logger.info("(security)user bbdd: ",user.username,"/// tipo: ",user.usertype)
                #security_info sera: headers +  (tor+ proxy)+ (ciudad, pais..)
                #current_user = get_jwt_identity()
                #claims=get_jwt()
                #usertype = claims['usertype']
                #userprofile = claims['userprofile']
            if usage.enQuota(user) :                
                usage.usage(user)
                #encabezados = dict(clienteHeaders.get_allHeaders())
                
                #sec= {'tor':security.using_tor(ip_cliente), 'proxy':clienteHeaders.get_ip_cliente()[1],'proxy_list':clienteHeaders.get_ip_cliente()[2]}
                sec= {'tor':security.using_tor(ip_cliente)}                
                
                subnets_file = os.path.join(configuracion.listas_PATH, 'firehol_level1.netset') 
                proxies_file = os.path.join(configuracion.listas_PATH, 'firehol_proxies.netset') 
                resp, subred = security.search_ip_in_subnets(ip_cliente, subnets_file)

                with open(proxies_file, 'r') as archivo:  
                # Mapea el archivo a la memoria
                    mm = mmap.mmap(archivo.fileno(), 0, access=mmap.ACCESS_READ)
                # Llama a la función buscar_ip_binaria con la IP buscada
                    esProxy = security.buscar_ip_binaria(mm, ip_cliente, inicio=34)
       
                #esProxy = security.buscar_ip_recursivaP(proxies_file, ip_cliente,inicio=34)                
                
                content={}
                json_data = {}
                if bogonip==False :
                    geoIPdata_content = geoIPdata.performGeoData(ip_cliente)
                    #IPcontent={'city':geoIPdata.performGeoData(ip_cliente)['city'],'continent':geoIPdata.performGeoData(ip_cliente)['continent'], 'country_code':geoIPdata.performGeoData(ip_cliente)['country_code'], 'country_name':geoIPdata.performGeoData(ip_cliente)['country_name']}
                    geoIPcontent={'city':geoIPdata_content['city'],'continent':geoIPdata_content['continent'], 'country_code':geoIPdata_content['country_code'], 'country_name':geoIPdata_content['country_name']}
                    juis=ipjuis.performWhoIs(ip_cliente)                    
                    sec["bogon"]=False
                    
                else:# si es bogon, no hay datos geo ni asn                       
                    json_data = {"messageThreat": "Bogon IP, potentially dangerous", "ip_address": str(ip_cliente), "subnet": "", "subnets_file": "", "asn":"", "nets_name": "" , "abuse_contact": ""}
                    sec["bogon"]=True
                    return jsonify(json_data, sec)   
                    
                if resp==True :  #la ip esta en una lista de amenazas
                    #print(f"La dirección IP {ip_cliente} está en subred {subred}  del archivo {subnets_file}")            
                    json_data = {"messageThreat": "IP potentially dangerous", "ip_address": str(ip_cliente), "subnet": str(subred), "subnets_file": str(subnets_file), "asn":juis['asn'], "nets_name": juis['nets'][0]['name'] , "abuse_contact": juis['nets'][0]['emails']}            
                else:#la ip NO esta en una lista de amenazas                                
                    json_data = {"messageThreat": "IP NOT dangerous", "ip_address": str(ip_cliente)}
                    #content = jsonify(dict(encabezados),sec,IPcontent)                
                
                if esProxy!=False :  #la ip esta en una lista de proxies
                    json_data["messageProxy"]= "IP anonimized with a proxy : "+str(esProxy)
                    json_data["asn"]=juis['asn']
                    json_data["ip_address"]= str(ip_cliente) 
                    json_data["messageThreat"]= "IP potentially dangerous"
                    json_data["nets_name"]= juis['nets'][0]['name']
                    json_data["abuse_contact"]= juis['nets'][0]['emails'] 
                else:#la ip NO esta en una lista de proxies                                
                    json_data["messageProxy"]= "IP NOT from proxy"
                    json_data["ip_address"]= str(ip_cliente)
                 
                      
                content = jsonify(json_data, sec,geoIPcontent)   
            else:#  si usage.enQuota(user) devuelve False  pq ha alcanzado los usos pagados                   
                 return jsonify({"message": "User has reached its usage quota. Go to https://www.privacy4ip.com to update or upgrade."}), 401   
        else:# no hay usuario correspondiente al token o Token inválido en bbdd
                return jsonify({"message": "Token does not correspond to user in database or does not correspond to user profile security"}), 401
    except KeyError as e:
              logger.info("Error en security:", e)
              return jsonify({"message": "Token not valid"}), 401
        
            
    return content 
 
 
 #=====================================================================================================================================================
  
  
@app.route("/fuzzygeo/<string:ip_cliente>", methods=['GET'])
@jwt_required()

def fuzzyGeo_info(ip_cliente):

    try:
        token_arg = request.args.get('jwt')
        if security.validate_ip_address(ip_cliente)==None:       
             return jsonify({"message": "IP NOT valid", "ip_address": str(ip_cliente)}), 401   
        if security.is_bogon(ip_cliente):# check if bogon ip.
             return jsonify({"message": "Bogon IP. No geodata for bogon ip's", "ip_address": str(ip_cliente)}), 401
        user = User.query.filter_by(token=token_arg).first()
        if user and user.userprofile=="fuzzygeo":#cliente tiene perfil fuzzygeo
            # tengo el usuario correspondiente al token
            if usage.enQuota(user) :                
                usage.usage(user)   
                #fuzzyGeo_info sera: fuzzyGeoLocalizacion
                ipinfo_bdGeoIP=geoIPdata.performGeoData(ip_cliente)                
                postal=ipinfo_bdGeoIP['postal_code']
                pais=ipinfo_bdGeoIP['country_code']                 
                if not postal or postal=="None":
                  postal='0'  
                aproxZone_list=fuzzyGeoLoc.obtener_aproxZone(postal, pais)
                #aproxZone_list=fuzzyGeoLoc.obtener_aproxZone('20018', 'es')
                
                lat_pto_Ciudad=ipinfo_bdGeoIP['latitude']
                lon_pto_Ciudad=ipinfo_bdGeoIP['longitude']
                lat_pto_Exacto=float(aproxZone_list[0]['lat'])
                lon_pto_Exacto=float(aproxZone_list[0]['lon'])    
                fuzzy_geoloc_lat,fuzzy_geoloc_lon, radius=fuzzyGeoLoc.get_fuzzy_ptomedio(lat_pto_Exacto,lon_pto_Exacto,lat_pto_Ciudad,lon_pto_Ciudad)
                                
                aproxZone_list[0].pop('lat')
                aproxZone_list[0].pop('lon')    
                my_list = [fuzzy_geoloc_lat, fuzzy_geoloc_lon, radius]
                aproxZone_list[0]['boundingcircle'] = my_list
                
                resp = jsonify(aproxZone_list[0])

            else:
                #  si usage.usage(user) devuelve False  pq ha alcanzado los usos pagados                   
                 return jsonify({"message": "User has reached its usage quota. Go to https://www.privacy4ip.com to update or upgrade."}), 401    
        else:# no hay usuario correspondiente al token o Token inválido en bbdd
                return jsonify({"message": "Token does not correspond to user in database or does not correspond to user profile fuzzygeo"}), 401
    except KeyError as e:
              logger.info("Error en fuzzygeo:", e)
              return jsonify({"message": "Token not valid"}), 401
        
            
    return resp   
 
 #=====================================================================================================================================================
  
    
@app.route("/asn/<string:ip_cliente>",methods=['GET'])
@jwt_required()

def asn_info(ip_cliente):
 
    try:
        if security.validate_ip_address(ip_cliente)==None:#la ip de la peticion NO es valida       
             return jsonify({"message": "IP NOT valid", "ip_address": str(ip_cliente)}), 401   
        if security.is_bogon(ip_cliente):# check if bogon ip.
             return jsonify({"message": "Bogon IP. No asn(isp) for bogon ip's", "ip_address": str(ip_cliente)}), 401
        token_arg = request.args.get('jwt')
        user = User.query.filter_by(token=token_arg).first()
        if user and user.userprofile=="asn":#cliente tiene perfil asn
            # tengo el usuario correspondiente al token
                if  usage.enQuota(user) :                
                    usage.usage(user)
                    content = ipjuis.performWhoIs(ip_cliente)            
                    resp = jsonify(content)
                else: #  si usage.usage(user) devuelve False  pq ha alcanzado los usos pagados                   
                    return jsonify({"message": "User has reached its usage quota. Go to https://www.privacy4ip.com to update or upgrade."}), 401   
                #return jsonify({"message": "Operación completada exitosamente"})
        else:# no hay usuario correspondiente al token o Token inválido en bbdd
            return jsonify({"message": "Token does not correspond to user in database or does not correspond to user profile ASN(isp)"}), 401
    except KeyError:
        logger.info("KeyError en asn: ",KeyError)
        return jsonify({"message": "Token not valid"}), 401
    
        
    return resp  


 
 #=====================================================================================================================================================
 
'''
@app.route("/remotedevice/<string:ip_cliente>/<path:headers_cliente>",methods=['GET'])
#@app.route("/remotedevice",methods=['GET','POST'])
@jwt_required()

def remotedevice_info(ip_cliente, headers_cliente):
    
    if security.validate_ip_address(ip_cliente)!=None:
        #device_info sera: user_agent + (ciudad, pais..)
        #print("headers_cliente : "+ headers_cliente)
        headers={}
        if remoteHeaders.json_validator(headers_cliente) :   
            headers=json.loads(headers_cliente)
        #agente=dict(remoteHeaders.get_user_agent(headers_cliente))
        #allheaders=dict(remoteHeaders.get_allHeaders(headers))
        #IPcontent=geoIPdata.performGeoData(ip_address)['ipCity']
        #print(geoIPdata.performGeoData(ip_cliente))
        IPcontent={'city':geoIPdata.performGeoData(ip_cliente)['city'],'continent':geoIPdata.performGeoData(ip_cliente)['continent'], 'country_code':geoIPdata.performGeoData(ip_cliente)['country_code'], 'country_name':geoIPdata.performGeoData(ip_cliente)['country_name']}
       
        
        resp = jsonify(ip_cliente,IPcontent,headers)
    
    else:
        json_data = {"message": "IP no valida", "ip_address": str(ip_cliente)}   
        # Convertir el diccionario a una cadena JSON y retornarla
        resp = jsonify(json_data)
        resp.status_code = 400 # here we change the status code to 400 (typical code for request errors)
    
    return resp  

'''
 
 #=====================================================================================================================================================
 
 

@app.route("/useraccount",methods=['GET', 'POST'])
#@jwt_required()

def useraccount_info():  

    #access_token = request.headers.get('Access-Token')
    access_token = request.cookies.get('access_token_cookie')
    username=None
    
    if request.method == 'POST': 
        print('post en formulario usseracconut: request')
     #for key, value in request.form.items():
            #print(f'{key}: {value}')
    #se proceso formulario porque ha habido cambios 
        form_firstname = request.form.get('first_name')
        form_lastname = request.form.get('last_name')
        new_username = form_firstname+" "+form_lastname
        form_usercompany = request.form.get('user_company')
        form_email = request.form.get('email')
        
        # ... procesar los datos del formulario y actualizar la base de datos        
        existing_user = User.query.filter_by(username=session['username']).first()
        #print(existing_user)
        existing_user.username = str(new_username)
        existing_user.useremail = str(form_email)
        existing_user.usercompany = str(form_usercompany) 
        
        try:
            flag_modified(existing_user, "username")
            db.session.merge(existing_user)
            #db.session.flush()
            db.session.commit()
            flag_modified(existing_user, "useremail")
            db.session.merge(existing_user)
            db.session.commit()
            flag_modified(existing_user, "usercompany")
            db.session.merge(existing_user)
            db.session.commit()
            session['username'] = new_username
            session['usercompany'] = form_usercompany
            session['useremail'] = form_email      
        except Exception as e:
            print("excepcion db :",str(e))
            db.session.rollback()
            
        resp = make_response(redirect('/useraccount')) 
        return resp
        
    else:
       if request.method == 'GET':        
        # Verificar credenciales
            for key, value in request.args.items():
                print(f'{key}: {value}')
            if request.args.get('stripe_customer_id'):# si el request.args incluye un stripe_customer_id, es pq vengo desde stripe
                stripe_customer_id=request.args.get('stripe_customer_id')
                user = User.query.filter_by(stripe_client_id=stripe_customer_id).first() 
                print("plan actual: ",user.usertype)
                print("plan nuevo: ",session['chosen_price'])

                if session['chosen_price']==configuracion.enviroment.stripe_price_b:# se ha suscrito a plan business
                   user.usertype="Business"
                   session['userplan'] = "Business"
                elif session['chosen_price']==configuracion.enviroment.stripe_price_c: # se ha suscrito a plan corporation
                   user.usertype="Corporation"
                   session['userplan'] = "Corporation"
                else: 
                   # se ha suscrito a plan unlimited 
                   user.usertype="Unlimited" 
                   session['userplan'] = "Unlimited"
                
                print("usuario : ",user.username, " // nuevo plan:",session['userplan']) 
                #guardar en session username, usertype, userprofile,...
                session['username'] = user.username
                session['password'] = user.password
                #session['userplan'] = user.usertype
                session['userprofile'] = user.userprofile
                session['usercompany'] = user.usercompany
                session['useremail'] = user.useremail
                session['usage_count'] = user.usage_count
                session['created'] = user.created
                session['token'] = user.token
                session['stripe_client_id'] = user.stripe_client_id     
                try:
                    flag_modified(user, "usertype")
                    db.session.merge(user)
                    #db.session.flush()
                    db.session.commit()                    
                    
                except Exception as e:
                    print("excepcion db :",str(e))
                    db.session.rollback()  
                    return redirect('/login?message='+'El usuario NO existe en nuestra base de datos. Compruebe los datos introducidos.')
                
                # Devolver el token como respuesta
                resp = make_response(redirect('/useraccount')) 
                #resp = make_response(redirect('cuenta.html'))
                resp.set_cookie('access_token_cookie', user.token)                
                return resp  
            
            else:# info de usuario para mostrar
            #si vengo de register, tendre un mensaje de nuevo usuario
                message = request.args.get('message')
                print(" el message : "+ str(message))
                
                if 'username' in session:
                    username = session['username']
                    userplan = session['userplan']
                    print("userplan : "+ str(userplan))
                    userprofile = session['userprofile']
                    password = session['password']
                    usercompany = session['usercompany'] 
                    useremail = session['useremail']
                    usage_count = session['usage_count']
                    created = session['created']
                    access_token = session['token']                
                
                    ip_address,es_proxy, proxy_list=clienteHeaders.get_ip_cliente()    
                    #--obtener agente de cliente---
                    user_agent=clienteHeaders.get_user_agent()    
                    #--obtener toda la cabecera http---
                    headers_dict=clienteHeaders.get_allHeaders()
                    #access_token = request.headers.get('Access-Token')
                    access_token = request.cookies.get('access_token_cookie')
                    
                    #---esta usando TOR?--
                    is_using_tor=security.using_tor(ip_address)
                    #is_using_tor=security.using_tor('85.85.40.166')
                    
                    #calculo los usos que quedan
                    usage_rest=0
                    if userplan == 'Free':
                        usage_rest= configuracion.enviroment.USAGE_QUOTA_1-usage_count
                    if userplan == 'Business':
                        usage_rest= configuracion.enviroment.USAGE_QUOTA_2-usage_count
                    if userplan == 'Corporation':
                        usage_rest= configuracion.enviroment.USAGE_QUOTA_3-usage_count 
                    
                    
                    #--devuelvo datos para insertarlos en cuenta.html
                    return render_template("cuenta.html", ip_address=ip_address, es_proxy=es_proxy, user_agent=user_agent, headers_dict=headers_dict, is_using_tor=is_using_tor, access_token=access_token, username=username, userplan=userplan, userprofile=userprofile, usercompany = usercompany, useremail = useremail, usage_count = usage_count, usage_rest=usage_rest, created = created, message = message)
            
            

 
 #=====================================================================================================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Recuperar credenciales del usuario
    #username = request.json.get('username', None)
    
    
   if request.method == 'POST':#formulario de login
        username =request.form.get('username')
        password =request.form.get('password')
        # Verificar credenciales
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password) :
            
            #guardar en session username, usertype, userprofile
            session['username'] = username
            session['password'] = user.password
            session['userplan'] = user.usertype
            session['userprofile'] = user.userprofile
            session['usercompany'] = user.usercompany
            session['useremail'] = user.useremail
            session['usage_count'] = user.usage_count
            session['created'] = user.created
            session['token'] = user.token
            session['stripe_client_id'] = user.stripe_client_id
            #print('post en formulario login: session')
            #for key, value in session.items():
            #    print(f'{key}: {value}')
            
            # Devolver el token como respuesta
            resp = make_response(redirect('/useraccount')) 
            #resp = make_response(redirect('cuenta.html'))
            resp.set_cookie('access_token_cookie', user.token)
            
            return resp
        else:
            return redirect('/login?message='+'El usuario NO existe en nuestra base de datos. Compruebe los datos introducidos.')
   else:
    if request.method == 'GET':        
        # Verificar credenciales
        if request.args.get('stripe_customer_id'):# si el request.args incluye un stripe_customer_id, es pq vengo desde stripe
                stripe_customer_id=request.args.get('stripe_customer_id')
                user = User.query.filter_by(stripe_client_id=stripe_customer_id).first() 
                print("plan en login/get: ",user.usertype)
                if user :                    
                    #guardar en session username, usertype, userprofile,...
                    session['username'] = user.username
                    session['password'] = user.password
                    session['userplan'] = user.usertype
                    session['userprofile'] = user.userprofile
                    session['usercompany'] = user.usercompany
                    session['useremail'] = user.useremail
                    session['usage_count'] = user.usage_count
                    session['created'] = user.created
                    session['token'] = user.token
                    session['stripe_client_id'] = user.stripe_client_id
                    #print('post en formulario login: session')
                    #for key, value in session.items():
                    #    print(f'{key}: {value}')
                    
                    # Devolver el token como respuesta
                    resp = make_response(redirect('/useraccount')) 
                    #resp = make_response(redirect('cuenta.html'))
                    resp.set_cookie('access_token_cookie', user.token)
                    
                    return resp
                else:
                    return redirect('/login?message='+'El usuario NO existe en nuestra base de datos. Compruebe los datos introducidos.')
    #aun no he rellenado el formulario login

    return render_template('login.html', message=request.args.get('message'))

 
 #=====================================================================================================================================================
   
    
@app.route('/signup', methods=['GET', 'POST'])#registro de un nuevo usuario

def signup():
    
    if request.method == 'POST':
        # Recuperar credenciales del usuario del formulario
        username =request.form.get('username')
        password =request.form.get('password')
        userprofile =request.form.get('profile')
        useremail =request.form.get('email')
        usercompany =request.form.get('companyname') 
        userplan =request.form.get('plan') #en principio, todos los usuarios nuevos seran del plan FREE
        #for field in request.form:
           # value = request.form.get(field)
           # print(f"{field}: {value}")    
        
        
        # Verificar si el usuario ya existe 
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            #flash('El usuario ya existe, por favor seleccione otro nombre de usuario.')
            #return redirect('/signup')
            return redirect('/signup?message='+'El usuario ya existe, por favor seleccione otro nombre de usuario.')
        #creo nuevo cliente en stripe --> llegara webhook customer_created
        new_stripe_customer = stripe.Customer.create(
            name=username, 
            email=useremail,
            description=usercompany+"//"+userprofile+"//"+userplan,)
        print("new stripe customer :" + str(new_stripe_customer.id))

        #creo nuevo usuario en bbdd
        new_user = User(username=username,
                        password=password,
                        useremail=useremail,
                        userprofile=userprofile,
                        usertype=userplan,
                        usercompany=usercompany,
                        created=datetime.datetime.now(),
                        usage_count=0,
                        stripe_client_id=new_stripe_customer.id)
         
        db.session.add(new_user)# añadir nuevo usuario a bbdd
        #db.session.commit()
        
        #expires = datetime.datetime.now() + configuracion.JWT_ACCESS_TOKEN_EXPIRES  
        expires = datetime.datetime.now() + enviroment.JWT_ACCESS_TOKEN_EXPIRES        
        # Crear el token de acceso
        #additional_claims = {'username':username, 'userprofile': new_user.userprofile, 'userplan': new_user.usertype,'created_at': datetime.datetime.now(),
                #'expires_at': expires}
        #si utilizo un additional_claims mas corto, obtengo un token mas corto, pero igualmente seguro
        additional_claims = {'username':username, 'usertype': new_user.usertype}
        access_token = create_access_token(identity=new_user.id, additional_claims=additional_claims)
        
        new_user.token = access_token
        db.session.commit()
        
        session['username'] = new_user.username
        session['password'] = new_user.password
        session['userplan'] = new_user.usertype
        session['userprofile'] = new_user.userprofile
        session['usercompany'] = new_user.usercompany
        session['useremail'] = new_user.useremail
        session['usage_count'] = new_user.usage_count
        session['created'] = new_user.created
        session['token'] = access_token 
        session['stripe_client_id'] = new_user.stripe_client_id  
        
        message = 'New user ' + str(username) +" :: "+ str(new_user.usercompany) + ' successfully created!'
        resp = make_response(redirect(url_for('useraccount_info', message=message)))
         # Devolver el token como respuesta         
        resp.set_cookie('access_token_cookie', access_token)
        return resp
        
        #return redirect('/useraccount?username='+username+'&password='+password)
        #return redirect('/useraccount')
    else:    
        return render_template('register.html', message=request.args.get('message'))
    
  
 #=====================================================================================================================================================
  
  
@app.route('/logout')
#@jwt_required()
def logout():
    
    #for key, value in session.items():
    #            print(f'{key}: {value}')
    print("logout")
    if session.get('username'):   #si estamos en sesion de un usuario     
        #user = User.query.filter_by(username=session['username']).first()
        #if user:
        # Eliminar toda la información de la sesión del usuario
            session.clear()            
            return make_response(redirect('/'))
       #else:
       #     return 'Logout failed', 200 
    # Redirigir al usuario a la página de inicio de sesión
    return make_response(redirect('/'))
    
  
 #=====================================================================================================================================================
 
  
@app.route('/pricing')
def pricing():
    return render_template('pricing.html')
 
 #=====================================================================================================================================================


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':#formulario de contacto
        
        # Recuperar credenciales del usuario del formulario
        fname =request.form.get('fname')
        lname =request.form.get('lname')
        emailfrom =request.form.get('email')
        message =request.form.get('message')

        msg = EmailMessage()
        msg.set_content(f"Nombre: {fname}{lname}\nCorreo origen: {emailfrom}\nMensaje:\n{message}")

        msg['Subject'] = 'Mensaje desde tu sitio web privacyIP'
        msg['From'] = emailfrom
        msg['To'] = 'privacyipapi@gmail.com, euroipapi@proton.me'

        try:
            server = SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login('privacyipapi@gmail.com', 'coxo daon pnup pfdm')
            server.send_message(msg)
            server.quit()
            return render_template('contact.html', message='Message successfully sent!')
        except Exception as e:
            print(f"An error occurred: {e}")
            return render_template('contact.html', message='An error occurred while sending the email. Please try again later.')


        #message =message.encode('utf-8')
        #msg = Message('Mensaje desde tu sitio web privacyIP', sender=emailfrom, recipients=['privacyipapi@gmail.com','euroipapi@proton.me'])
        #msg.body = f"Nombre: {fname}{lname}\nCorreo origen: {emailfrom}\nMensaje:\n{message}"
        #msg.body = msg.body.encode('utf-8')
        #print("msg.body2 : ",msg.body)
        #try:
            #mail.send(msg)
            #return render_template('contact.html', message='Message successfully sent!')
        #except Exception as e:
            #print(f"An error occurred: {e}")
            #return render_template('contact.html', message='An error occurred while sending the email. Please try again later.')
    else:    
    #si no se ha rellenado el formulario de contacto, simplemente mostrar pagina contacto   
        return render_template('contact.html')
    
#=====================================================================================================================================================
 
  
@app.route('/docs')
def docs():
    return render_template('docs.html') 

   
#=====================================================================================================================================================


@app.route('/product')
def product():
    #for key, value in session.items():
    #          print("producto : "+f'{key}: {value}')
    print("YOUR_DOMAIN : ",enviroment.YOUR_DOMAIN)
    return render_template('checkout.html')    
    
    
#=====================================================================================================================================================
#=====================================================================================================================================================
#=====================================================================================================================================================

stripe.api_key=enviroment.STRIPE_API_KEY


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    print("create-checkout-session form : ", request.form)
    if request.form['lookup_key']=="planB":
        session['chosen_price']=configuracion.enviroment.stripe_price_b
    if request.form['lookup_key']=="planC":
        session['chosen_price']=configuracion.enviroment.stripe_price_c 
        
           
    print ("precio seleccionado : ", session['chosen_price'])
    try:
        '''prices = stripe.Price.list(
            lookup_keys=[request.form['lookup_key']],
            expand=['data.product']
        )
        '''
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {#'price': prices.data[0].id,
                    'price': session['chosen_price'],#request.form['lookup_key'],
                    'quantity': 1,},
            ],
            mode='subscription',            
            success_url=enviroment.YOUR_DOMAIN + '/create-portal-session?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=enviroment.YOUR_DOMAIN + '/subscripcion_cancelada',
            #client_reference_id=session['stripe_client_id'],
            customer= session['stripe_client_id'],
            metadata={'client_id': session['stripe_client_id']}
        )
        #print("checkout_session : "+str(checkout_session))
        return redirect(checkout_session.url, code=303)
    
    except Exception as e:
        print(e)
        return "Server error", 500


@app.route('/create-portal-session', methods=['GET','POST'])
def customer_portal():
    session_id = request.args.get('session_id')
    #session_id =request.form.get('session_id')
    print('create-portal-session request : ',session_id)
    # For demonstration purposes, we're using the Checkout session to retrieve the customer ID.
    # Typically this is stored alongside the authenticated user in your database.    
    checkout_session = stripe.checkout.Session.retrieve(session_id)
    #print("checkout_session : ",checkout_session)
    # This is the URL to which the customer will be redirected after they are
    # done managing their billing with the portal.
    portalSession = stripe.billing_portal.Session.create(
        customer=checkout_session.customer,
        return_url=enviroment.YOUR_DOMAIN + '/useraccount?stripe_customer_id=' + checkout_session.customer + '&message=Succesfully Subscription' ,
        #return_url=enviroment.YOUR_DOMAIN + '/login?stripe_customer_id=' + checkout_session.customer + '&message=Succesfully Subscription' ,
    )
    return redirect(portalSession.url, code=303)



@app.route('/webhook', methods=['POST'])
@csrf.exempt #csrf tiene conflicto con stripe. En su lugar usamos signature = request.headers.get('stripe-signature')
def webhook_received():
    
    webhook_secret = enviroment.stripe_webhook_secret  
   
    request_data = json.loads(request.data)
          
    print("Tipo de webhook: "+str(request_data['type']))
    if webhook_secret:
        # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
        signature = request.headers.get('stripe-signature')
        #print("stripe-signature: "+str(signature))
        try:
            event = stripe.Webhook.construct_event(payload=request.data, sig_header=signature, secret=webhook_secret)  
             # Get the type of webhook event sent - used to check the status of PaymentIntents.
            event_type = event['type']
            data_obj=event['data']['object']                   
        except Exception as e:
            print('Exception : ' + str(e)) 
            return jsonify(success=False)         
    else:
        data = request_data['data']
        event_type = request_data['type']


    if event_type == 'checkout.session.completed':
        webhooks.webhook_checkout_session_completed(data_obj)

    elif event_type =='customer.subscription.created':
        webhooks.webhook_customer_subscription_created(data_obj) 

    elif event_type == 'customer.subscription.updated':
        webhooks.webhook_customer_subscription_updated (event, data_obj)
        
    elif event_type == 'customer.subscription.deleted':
        webhooks.webhook_customer_subscription_updated (event, data_obj)

    elif event_type == 'customer.created' :
        webhooks.webhook_customer_created(event, data_obj)

    elif event_type == 'invoice.payment_failed': 
        webhooks._invoice_payment_failed (event, data_obj)
        
    elif event_type == 'customer.subscription.past_due': 
        webhooks._customer_subscription_past_due(event, data_obj)

    return jsonify({'status': 'success'}, 200)




@app.route('/subscripcion_cancelada')
def subscripcion_cancelada():
    return render_template('cancel.html')   


@app.route('/subscripcion_exitosa')
def subscripcion_exitosa():    
    checkout_session_id = request.args.get('session_id')    
    return render_template('success.html', session_id=checkout_session_id)




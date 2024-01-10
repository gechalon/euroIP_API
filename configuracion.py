import os
from datetime import datetime, timedelta
from decouple import config
from pathlib import Path
import logging
# Inicializa el sistema de registro
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class Config:
    pass

db_url = os.environ.get('DATABASE_URL', 'C:\\Users\\gorka\\Proyectos\\euroIP_flask\\bbdd\\')
sqlite_url = os.environ.get('DATABASE_URL', 'sqlite:///C:\\Users\\gorka\\Proyectos\\euroIP_flask\\bbdd\\')
DB_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'bbdd')#os.path.join(os.path.dirname(__file__), 'bbdd')
listas_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'listas')
print("DB_PATH desde os.path.abspath : "+str(DB_PATH))
print("listas_PATH desde os.path.abspath : "+str(listas_PATH))
print("db_url desde os.environ : "+str(db_url))
print("FLASK_ENV desde os.environ : ",os.environ.get('FLASK_ENV'))

#################################################################################################################################################
 
class DevelopmentConfig(Config):
    DEBUG = True
    YOUR_DOMAIN='http://localhost:5000'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///C:\\Users\\gorka\\Proyectos\\euroIP_flask\\bbdd\\test.db'
    #db_url="C:\\Users\\gorka\\Proyectos\\euroIP_flask\\bbdd"
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_TOKEN_LOCATION = 'query_string'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    #JWT_COOKIE_CSRF_PROTECT = True
    #cookies seguras dan errores en entorno de desarrollo
    #JWT_COOKIE_SECURE = True
    #SESSION_COOKIE_SECURE= True
    JWT_COOKIE_CSRF_PROTECT = False
    #DB_PATH=os.path.abspath('C:\\Users\\gorka\\Proyectos\\euroIP_flask\\bbdd\\')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=30)
    #DB_PATH = os.path.join(os.path.dirname(__file__), 'bbdd')
    USAGE_QUOTA_1=6000 #contador de usos de usertype=free. Hasta 6 mil usos/mes
    USAGE_QUOTA_2=100000 #contador de usos de usertype=business. Hasta 100 mil usos/mes
    USAGE_QUOTA_3=1000000 #contador de usos de usertype=corporation. Hasta 1 millon usos/mes
    #SERVER_NAME = 'flaskcms.pythonanywhere.com'
    # Obtener la clave secreta de webhook de Stripe desde la variable de entorno
    STRIPE_API_KEY=os.environ.get('STRIPE_API_KEY')
    stripe_webhook_secret = os.environ.get('stripe_webhook_secret')
    

    
class ProductionConfig(Config):
    DEBUG = False
    #YOUR_DOMAIN='https://a007-85-85-247-203.ngrok-free.app'
    YOUR_DOMAIN='http://localhost:8080'

    #SQLALCHEMY_DATABASE_URI = config('DATABASE_URL')
    #db_url = os.environ.get('DATABASE_URL', 'sqlite:///C:\\Users\\gorka\\Proyectos\\euroIP_flask\\bbdd\\test.db')
    #SQLALCHEMY_DATABASE_URI = os.path.join(sqlite_url, 'test.db')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(DB_PATH, 'test.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    #JWT_COOKIE_SECURE = True
    #SESSION_COOKIE_SECURE= True
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_TOKEN_LOCATION = 'query_string'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    #JWT_COOKIE_CSRF_PROTECT = True
    #cookies seguras dan errores en entorno de desarrollo
    #JWT_COOKIE_SECURE = True
    #SESSION_COOKIE_SECURE= True
    JWT_COOKIE_CSRF_PROTECT = True

    #listas_path = Path("C:\\Users\\gorka\\Proyectos\\euroIP_flask\\bbdd\\firehol_level1.netset")  
    #listas_path2 = Path(r"C:\Users\gorka\Proyectos\euroIP_flask\bbdd\firehol_level1.netset")
    #listas_path3 = Path("C:/Users/gorka/Proyectos/euroIP_flask/bbdd/firehol_level1.netset")
    
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=30)
    
    USAGE_QUOTA_1=6 #contador de usos de usertype=free. Hasta 6 mil usos/mes
    USAGE_QUOTA_2=100000 #contador de usos de usertype=business. Hasta 100 mil usos/mes
    USAGE_QUOTA_3=1000000 #contador de usos de usertype=corporation. Hasta 1 millon usos/mes
    #SERVER_NAME = 'flaskcms.pythonanywhere.com'
    # Obtener la clave secreta de webhook de Stripe desde la variable de entorno
    STRIPE_API_KEY=os.environ.get('STRIPE_API_KEY')
    stripe_webhook_secret = os.environ.get('stripe_webhook_secret')
    stripe_price_b="price_1O2xaXDpa8n85JEH4TJg5zmR"#En modo prueba
    stripe_price_c="price_1O2ANRDpa8n85JEHh5OQxd3Y"#En modo prueba
   
    

class cloudServerConfig(Config):
    DEBUG = False
    #--------------------------------------------------------  
    YOUR_DOMAIN='https://www.privacy4ip.com'
    #--------------------------------------------------------  
    #SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(DB_PATH, 'test.db')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(DB_PATH, 'privacyIPusers.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_TOKEN_LOCATION = 'query_string'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    JWT_COOKIE_CSRF_PROTECT = True

    #level1_path = Path("/home/debian/listas/firehol_level1.netset")
    #proxies_path = Path("/home/debian/listas/firehol_proxies.netset")

    #ruta_level1=os.path.join(listas_PATH, '/firehol_level1.netset')
    
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=30)
    
    USAGE_QUOTA_1=6000 #contador de usos de usertype=free. Hasta 6 mil usos/mes
    USAGE_QUOTA_2=100000 #contador de usos de usertype=business. Hasta 100 mil usos/mes
    USAGE_QUOTA_3=1000000 #contador de usos de usertype=corporation. Hasta 1 millon usos/mes

    # clave secreta de cuenta Stripe
    STRIPE_API_KEY=os.environ.get('STRIPE_API_KEY')
    stripe_webhook_secret = os.environ.get('stripe_webhook_secret')
    stripe_price_b="price_1O2tPXDpa8n85JEHFb1OoXlS"#En modo produccion
    #stripe_price_c="price_1O2ANRDpa8n85JEHh5OQxd3Y"#En modo prueba
    stripe_price_c="price_1O2tfiDpa8n85JEH0iU4dmZB"#En modo produccion


#########################################################################################################################################3

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'cloudserver': cloudServerConfig
}

    

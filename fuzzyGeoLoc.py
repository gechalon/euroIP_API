
#---------Bloque5----donde obtenemos geolocalizacion Fuzzy a partir de codigoPostal(lat, lon) y Ciudad(lat, lon)

# Importing the geodesic module from the library
from geopy.distance import geodesic
import math
import numpy as np
from geographiclib.constants import Constants
from geographiclib.geodesic import Geodesic
import random
import requests

from configuracion import logger


def get_bearing(lat1,lon1,lat2,lon2):
    dLon = lon2 - lon1;
    y = math.sin(dLon) * math.cos(lat2);
    x = math.cos(lat1)*math.sin(lat2) - math.sin(lat1)*math.cos(lat2)*math.cos(dLon);
    brng = np.rad2deg(math.atan2(y, x));
    #print("bearing antes de fuzzy:"+str(brng))
    #hacemos fuzzy tambien el bearing (desde -20% hasta +20%)
    desplaz=random.uniform(-brng/5, brng/5)
    brng=brng+desplaz
    #print("bearing despues de fuzzy:"+str(brng))
    if brng < 0: brng+= 360
    return brng

def get_distance(lat1,lon1,lat2,lon2):

  distancia=geodesic((lat1,lon1), (lat2,lon2)).km  
  #print("distancia :"+str(distancia)+" km")
  return distancia



def getEndpoint(lat1, lon1, bearing, desplaz):
    geod = Geodesic(Constants.WGS84_a, Constants.WGS84_f)
    d = geod.Direct(lat1, lon1, bearing, desplaz*1000)
    return d['lat2'], d['lon2']

def get_fuzzy_ptomedio(lat1,lon1,lat2,lon2):

  #distancia entre los ptos : real y centro ciudad. Usaremos distancia/2 como radio del circulo a dibujar
  distancia=get_distance(lat1,lon1,lat2,lon2)
  #print('distancia: '+str(distancia)+'km')
  #angulo que forma la linea del pto real al centro ciudad
  bear=get_bearing(lat1,lon1,lat2,lon2)
  #despalzmiento para hacerlo fuzzy: random entre y la mitad de distancia
  desplaz=random.uniform(0, distancia/2)
  #print('desplazamiento: '+str(desplaz))
  origen=(lat1,lon1)

  pto_medio_lat, pto_medio_lon=getEndpoint(lat1, lon1, bear, desplaz)

  return pto_medio_lat, pto_medio_lon, desplaz 


def get_content(url):

    headers = {'Content-Type': 'application/json;charset=UTF-8', 'Access-Control-Allow-Origin': '*'}
    content = None
    try:
        # Get content
        r = requests.get(url, headers=headers)
        # Decode JSON response into a Python dict:
        content = r.json()
    except requests.exceptions.HTTPError as e:
        logger.info("Bad HTTP status code:", e)
    except requests.exceptions.RequestException as e:
       logger.info("Network error:", e)

    return content  
    
def obtener_aproxZone(postal_code, country_code):
  
  aproxZone_list={}
  logger.info("postal : ", postal_code)
  #print("postal_code type: ", type(postal_code))
  if postal_code=='0' or postal_code==None or postal_code=='None':#Si no hay postal_code      
      aproxZone_list=get_content('https://nominatim.openstreetmap.org/search.php?country='+country_code+'&format=jsonv2')  
      logger.info("aproxZone sin postal : ", aproxZone_list)    
  else:
      try:
        #aproxZone_list=get_content('https://nominatim.openstreetmap.org/ui/search.html?postalcode='+postal_code+'&country='+country_code+'&format=jsonv2')      
        aproxZone_list=get_content('https://nominatim.openstreetmap.org/search.php?postalcode='+postal_code+'&countrycodes='+country_code+'&format=jsonv2')
      #aproxZone_json=get_content('https://nominatim.openstreetmap.org/search.php?postalcode=20018&countrycodes=es&format=jsonv2')
      except KeyError as e:
        logger.info("Error aprox zone:", e) 

  return aproxZone_list  
#---------FIN Bloque5----
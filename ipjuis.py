#---------Bloque1----importar paquetes, definir variables donde dejamos datos IPinfo

from ipwhois import IPWhois
from ipwhois.exceptions import ASNRegistryError
from pprint import pprint
import datetime
import json

ipCity= {}
ipOrg=""
ipIsp=""
ipAsn=""
ipData=""
myCity=""
myZip=''
#---------Fin Bloque1---- 

#---------Bloque2----hora actual servidor
def timeStamp():
    now = datetime.datetime.now()
    return now.strftime("[%Y-%m-%d %H:%M:%S] ")
#---------Fin Bloque2---- 

#---------Bloque3----ejecutar lookup_whois de libreria python
def performWhoIs(IP):

    #print(timeStamp() + "* Performing python's IPWHOIS on " + IP)    
   try:
        obj = IPWhois(IP, 1)
        res = obj.lookup_whois()
        return res
   except ASNRegistryError:
       return {'No ASN data': 'ASN lookup failed with no more methods to try.'}
   except Exception as e:
        return {'error':f"An error occurred: {e}"}
#---------Fin Bloque3---- 
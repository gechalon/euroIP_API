#---------Bloque4----leer de bbdd geoIP
import pygeoip 
import configuracion

#RUTABBDD='C:\\misArchivos\\bbdd\\geoIP\\'
RUTABBDD = configuracion.DB_PATH#configuracion.db_url

#geoipData = pygeoip.GeoIP(RUTABBDD+'GeoIP.dat')
geoipCity = pygeoip.GeoIP(RUTABBDD+'/GeoIPCity.dat')
#geoipOrg = pygeoip.GeoIP(RUTABBDD+'GeoIPOrg.dat')
#geoipIsp = pygeoip.GeoIP(RUTABBDD+'GeoIPISP.dat')
#geoipAsn = pygeoip.GeoIP(RUTABBDD+'GeoIPASNum.dat')


def performGeoData(IP):

 try: 
  ipCity = geoipCity.record_by_addr(IP) 
  #myCity= ipCity['city']
  #myZip=ipCity['postal_code']
  #ipOrg = geoipOrg.org_by_addr(IP) 
  #ipIsp = geoipIsp.isp_by_addr(IP) 
  #ipAsn = geoipAsn.asn_by_addr(IP)
  #ipData = geoipData.country_name_by_name(IP)

 except:
   ipCity ={}
   #myCity=myZip=ipData=ipAsn="N/A"


 #return ipCity, ipData, myCity, myZip, ipAsn
 return ipCity
#---------FIN Bloque4----
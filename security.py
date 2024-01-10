from stem.control import stem, Controller
#import json
import ipaddress
import re
from ipaddress import ip_network
from configuracion import logger
    
def using_tor(client_ip):
    """
    La función utiliza la biblioteca Stem para comunicarse con el controlador de Tor a través del puerto 9051 y autenticarse en él. Luego, comprueba si un nuevo circuito de enrutamiento de Tor está disponible, lo que indica que el cliente ha iniciado una nueva sesión de Tor.
    """
    try:
        # Create a new controller
        with Controller.from_port(port=9051) as controller:
            # Authenticate
            controller.authenticate()
            # Check if the client is using Tor
            is_using_tor = controller.is_newnym_available()
            return is_using_tor
    except stem.SocketError:
        # Unable to connect to Tor's control port
        return False
    except Exception as e:
        logger.info(f"An error occurred: {e}")
        return False    
    

def validate_ip_address(ip_string):
   try:
       ip_object = ipaddress.ip_address(ip_string.strip())
       logger.info("The IP address '{ip_object}' is valid.")
       return ip_string
   except ValueError:
       logger.info("The IP address '{ip_string}' is NOT valid")
       return None
       



# Función principal para determinar si una dirección IP está en alguna de las subredes en un archivo de texto
def search_ip_in_subnets(ip_address, subnets_file):
   try:
       # Crear objeto "ipaddress" para la dirección IP
       ip_to_find = ipaddress.ip_address(ip_address.strip())       
       # Leer archivo de texto con la lista de subredes
       with open(subnets_file, 'r') as f:
           subnets = f.read().splitlines()       
       # Filtrar las líneas que no comienzan con un número
       subnets = [subnet for subnet in subnets if re.match(r'^\d', subnet)]       
       # Iterar sobre la lista de subredes y buscar la dirección IP
       for subnet in subnets:
           # Extraer la dirección de red y la máscara de la subred utilizando expresiones regulares
           network, mask = re.match(r'(\d+\.\d+\.\d+\.\d+)/(\d+)', subnet).groups()
           # Crear un objeto "ipaddress" para la subred
           subnet_obj = ipaddress.ip_network(subnet, strict=False)
           # Comprobar si la dirección IP se encuentra dentro de la subred utilizando el método "overlaps"
           if ip_to_find in subnet_obj:
               return True, subnet    
       # Si la dirección IP no se encuentra en ninguna subred, retornar un mensaje indicando esto
       return False, subnet
   except ipaddress.AddressValueError:
       logger.error("Invalid IP address: {}".format(ip_address))
   except FileNotFoundError:
       logger.error("File not found: {}".format(subnets_file))
   except Exception as e:
       logger.error("An error occurred: {}".format(e))


'''def buscar_ip_recursiva(archivo, ip_buscada, inicio=None, fin=None):
    if inicio is None:#las primeras 33 lineas son comentarios, no IPs
       inicio = 34
    if fin is None:
       # Obtener la cantidad de líneas en el archivo
       archivo.seek(34) # Volver al inicio del archivo
       for i, _ in enumerate(archivo):
           pass
       fin = i
    print(inicio,fin)
   # Caso base: la lista está vacía o la IP no se encuentra en la lista
    if inicio > fin:
       return False
    
   # Calcular el punto medio de la lista
    medio = (inicio + fin) // 2
   # Mover el cursor al punto medio del archivo
    archivo.seek(medio)
    print(inicio,fin,medio)
    
   # Leer la IP en el punto medio
    ip_medio = archivo.readline().strip()
    print("ip_medio : ",ip_medio)
    # Verificar si la IP en el punto medio comienza con un número
    if not ip_medio[0].isdigit():
        # Si no comienza con un número, se busca en la mitad derecha del archivo
        return buscar_ip_recursiva(archivo, ip_buscada.strip(), medio + 1, fin)
        
    ip_buscada_obj = ipaddress.IPv4Address(ip_buscada.strip())
    
    try:
        ip_medio_obj = ipaddress.IPv4Address(ip_medio)
        print(str(ip_medio)+" es una ip")
    except ValueError:
        # Si la cadena no es una dirección IP válida, entonces es una subred
        print(str(ip_medio)+" es una subred")
        subnet_obj = ipaddress.IPv4Network(ip_medio.strip())
        if ip_buscada_obj in subnet_obj:#si la ip pertenece a la subred salgo devolviendo True y la subred
                return True   
        else: #si la ip NO pertenece a la subred--> asignamos a la ip del pto medio la ip mas alta de esa subred
                ip_medio_obj = subnet_obj.broadcast_address

    # Comparar las direcciones IP
    if ip_medio_obj == ip_buscada_obj:
        return True
    elif ip_medio_obj < ip_buscada_obj:
        # La IP buscada está en la mitad derecha del archivo
        return buscar_ip_recursiva(archivo, ip_buscada.strip(), medio + 1, fin)
    else:
        # La IP buscada está en la mitad izquierda del archivo
        return buscar_ip_recursiva(archivo, ip_buscada.strip(), inicio, medio - 1)
'''

def buscar_ip_binaria(mm, ip_buscada, inicio=None, fin=None):
    try:
        if fin is None:
            fin = mm.size()  # Si no se proporciona un fin, usamos el tamaño del mmap
        if inicio is None:
            inicio = 34#0

        while inicio < fin:
            medio = (inicio + fin) // 2
            mm.seek(medio)
            mm.readline()  # Mover al inicio de la siguiente línea
            linea = mm.readline().strip()  # Elimina el carácter de nueva línea al final de la línea
            subred = ipaddress.IPv4Network(linea.decode())

            ip_buscada = ipaddress.IPv4Network(ip_buscada)

            if ip_buscada.subnet_of(subred):
                return linea.decode()
            elif ip_buscada > subred:
                inicio = medio + 1
            else:
                fin = medio

        return False
    
    except ipaddress.AddressValueError:
        logger.error("Invalid IP address: {}".format(ip_buscada))
    except Exception as e:
        logger.error("An error occurred: {}".format(e))


def is_bogon(ip_address):
    for network in BOGON_NETWORKS:
        if ipaddress.ip_address(ip_address.strip()) in network:
            return True
    return False

BOGON_NETWORKS = [
    ip_network("0.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("100.64.0.0/10"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("172.16.0.0/12"),
    ip_network("192.0.0.0/24"),
    ip_network("192.0.2.0/24"),
    ip_network("192.168.0.0/16"),
    ip_network("198.18.0.0/15"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
    ip_network("224.0.0.0/4"),
    ip_network("240.0.0.0/4"),
    ip_network("255.255.255.255/32"),
    ip_network("::/128"),
    ip_network("::1/128"),
    ip_network("::ffff:0:0/96"),
    ip_network("::/96"),
    ip_network("100::/64"),
    ip_network("2001:10::/28"),
    ip_network("2001:db8::/32"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
    ip_network("fec0::/10"),
    ip_network("ff00::/8"),
    ip_network("2002::/24"),
    ip_network("2002:a00::/24"),
    ip_network("2002:7f00::/24"),
    ip_network("2002:a9fe::/32"),
    ip_network("2002:ac10::/28"),
    ip_network("2002:c000::/40"),
    ip_network("2002:c000:200::/40"),
    ip_network("2002:c0a8::/32"),
    ip_network("2002:c612::/31"),
    ip_network("2002:c633:6400::/40"),
    ip_network("2002:cb00:7100::/40"),
    ip_network("2002:e000::/20"),
    ip_network("2002:f000::/20"),
    ip_network("2002:ffff:ffff::/48"),
    ip_network("2001::/40"),
    ip_network("2001:0:a00::/40"),
    ip_network("2001:0:7f00::/40"),
    ip_network("2001:0:a9fe::/48"),
    ip_network("2001:0:ac10::/44"),
    ip_network("2001:0:c000::/56"),
    ip_network("2001:0:c000:200::/56"),
    ip_network("2001:0:c0a8::/48"),
    ip_network("2001:0:c612::/47"),
    ip_network("2001:0:c633:6400::/56"),
    ip_network("2001:0:cb00:7100::/56"),
    ip_network("2001:0:e000::/36"),
    ip_network("2001:0:f000::/36"),
    ip_network("2001:0:ffff:ffff::/64"),
]

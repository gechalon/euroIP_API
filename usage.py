from flask_jwt_extended import (JWTManager, jwt_required, create_access_token)
from models import User
from models import db
import configuracion
from sqlalchemy.orm.attributes import flag_modified
enviroment = None

def enQuota(user):
   
   usertype= user.usertype 
   # Verificar tipo de usuario
   if usertype=='Free' or usertype==None or usertype=="":
        # Verificar contador de usos. Hasta 6000 usos/mes
        #print(int(user.usage_count)," > ",int(configuracion.enviroment.USAGE_QUOTA_1), " :: ",int(user.usage_count) > int(configuracion.enviroment.USAGE_QUOTA_1))              
        if int(user.usage_count) >= int(configuracion.enviroment.USAGE_QUOTA_1):
            return False#, 'Free users can only use the API 6k times/month'
        else: return True
   elif usertype == 'Business':
        # Verificar contador de usos. Hasta 100000 usos/mes
        if user.usage_count >= int(configuracion.enviroment.USAGE_QUOTA_2):
            return False#, 'Business users can only use the API 100K times/month'
            #return {'message': 'Business users can only use the API 100K times/month'}, 401
        else: return True    
   elif usertype == 'Corporation':
        # Verificar contador de usos. Hasta 1M usos/mes
        if user.usage_count >= int(configuracion.enviroment.USAGE_QUOTA_3):
            return False#, 'Corporation users can only use the API 1M times/month'
        else: return True
   else:
        # No hay límite de uso para usuarios Unlimited
        return True
     

def usage(user):
   # Recuperar información del token
   #current_user = get_jwt_identity()
   #print("current_user : "+str(current_user))
   #claims=get_jwt()
   #print("claims : "+str(claims))
   #if user.usertype == claims['usertype']:
   
   print("user : ",user.username," con usage_count :",  user.usage_count)
   user.usage_count += 1
   
   # Actualizar contador de usos en la base de datos
   flag_modified(user, "usage_count")
   db.session.merge(user)
   db.session.commit()
   
   return {'message': 'Access granted'}, 200
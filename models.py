from flask_sqlalchemy import SQLAlchemy
#import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    usertype = db.Column(db.String(20), nullable=True, default='Free')#tipo de usuario segun plan de pagos
    useremail = db.Column(db.String(80), nullable=False)
    usercompany = db.Column(db.String(80), nullable=True)
    userprofile = db.Column(db.String(20), nullable=False)#tipo de usuario segun datos deseados: security,asn,device, fuzzygeo
    password = db.Column(db.String(80), nullable=False)
    usage_count = db.Column(db.Integer, default=0)#numero de usos de api, segun licencia
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    token = db.Column(db.String(4096), unique=True, nullable=True)
    stripe_client_id= db.Column(db.String(120), unique=True, nullable=True)#identificador de usuario en Stripe
    
    def __init__(self, username, password, usertype, userprofile, useremail, usercompany, usage_count, created, stripe_client_id):

        self.username = username
        #self.password = Bcrypt.generate_password_hash(password).decode('utf-8')
        self.password = generate_password_hash(password)
        self.usertype = usertype
        self.userprofile = userprofile
        self.useremail = useremail
        self.usercompany = usercompany
        self.created = created
        self.usage_count = usage_count
        self.stripe_client_id = stripe_client_id
        
    def __repr__(self):
        return '<User %r>' % self.username

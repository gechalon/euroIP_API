
import configuracion
from models import db
import stripe
from flask import session,jsonify,render_template
from sqlalchemy.orm.attributes import flag_modified

from models import User

from email.message import EmailMessage
from smtplib import SMTP

from configuracion import logger

def webhook_checkout_session_completed(data_obj):
    try:    
        checkout_session = stripe.checkout.Session.retrieve(data_obj['id'])
        logger.info("STRIPE checkout_session, ",checkout_session)
        # El valor de client_reference_id se encuentra directamente en checkout_session
        client_reference_id = checkout_session.customer
        subscription_id = checkout_session['subscription']
        subscription = stripe.Subscription.retrieve(subscription_id)
        line_item = subscription['items']['data'][0]
        price_id = line_item['price']['id']

        logger.info('🔔 checkout.session.completed : Payment succeeded! : ', client_reference_id, " /// price_id : ", price_id)
        if client_reference_id and price_id:   
            
            user1 = User.query.filter_by(stripe_client_id=client_reference_id).first()#obtengo el usuario de bbdd a partir de customer en el request
            logger.info("user en bbdd : "+str(user1)+" para client_reference_id : "+str(client_reference_id))
            if user1 :
                if  price_id==configuracion.enviroment.stripe_price_b:#cambiar el plan de pago (usertype) en bbdd             
                    user1.usertype="Business"#stripe_subscription
                elif   price_id==configuracion.enviroment.stripe_price_c:#cambiar el plan de pago (usertype) en bbdd             
                    user1.usertype="Corporation"#stripe_subscription 
                    
                flag_modified(user1, "usertype")
                db.session.merge(user1)
                db.session.commit()
                session['userplan'] = user1.usertype
                '''session['username'] = session['user_id']
                session['password'] = user1.password                    
                session['userprofile'] = user1.userprofile
                session['usercompany'] = user1.usercompany
                session['useremail'] = user1.useremail
                session['usage_count'] = user1.usage_count
                session['created'] = user1.created
                session['token'] = user1.access_token'''
                logger.info("cambiado en bbdd usuario: "+str(user1.username)+" al plan: "+str(user1.usertype))
    except Exception as e:
       logger.error("Error al procesar la sesión de pago: %s", e)


def webhook_customer_subscription_created(data_obj):       
    # El ID del precio (price) se encuentra en 
    price_id = data_obj['items']['data'][0]['plan']['id'] 
    #print("price_id : "+str(price_id))
    logger.info('Subscription created :', price_id)


def webhook_customer_subscription_updated (event, data_obj):
    logger.info('Subscription updated :', event.id)
    subscription = event['data']['object']
    previous_attributes = event['data']['previous_attributes']
    # Verificar si la suscripción ha sido renovada
    if 'current_period_start' in previous_attributes:
      if previous_attributes['current_period_start'] != subscription['current_period_start']:
          try:
              checkout_session = stripe.checkout.Session.retrieve(data_obj['id'])
              client_reference_id = checkout_session.customer
              if client_reference_id:
                 try:
                     user1 = User.query.filter_by(stripe_client_id=client_reference_id).first()
                     if user1:
                        user1.usage_count = 0
                        flag_modified(user1, "usage_count")
                        db.session.merge(user1)
                        db.session.commit()
                        logger.info("Changed in db user: %s usage count: %s", user1.username, user1.usertype)
                 except Exception as e:
                     logger.error("An error occurred while accessing the database: {}".format(e))
          except stripe.error.StripeError as e:
              logger.error("A Stripe error occurred: {}".format(e.user_message))
          except Exception:
              logger.error("Another problem occurred, maybe unrelated to Stripe.")



def webhook_customer_subscription_deleted (event, data_obj):
    # handle subscription canceled automatically based
    # upon your subscription settings. Or if the user cancels it.
    logger.info('Subscription canceled/deleted: %s', event.id)
    subscription = event['data']['object']
    try:
        checkout_session = stripe.checkout.Session.retrieve(data_obj['id'])
        client_reference_id = checkout_session.customer
        if client_reference_id:
            try:
                user1 = User.query.filter_by(stripe_client_id=client_reference_id).first()
                if user1:
                    user1.usage_count = 1000000
                    flag_modified(user1, "usage_count")
                    db.session.merge(user1)
                    db.session.commit()
                    logger.info("Changed in db user: %s usage count: %s", user1.username, user1.usertype)
            except Exception as e:
                logger.error("An error occurred while accessing the database: {}".format(e))
    except stripe.error.StripeError as e:
        logger.error("A Stripe error occurred: {}".format(e.user_message))
    except Exception:
        logger.error("Another problem occurred, maybe unrelated to Stripe.")




def webhook_customer_created(event, data_obj):
    logger.info("customer.created ID : ",data_obj['id'])
    try:
        existing_user = User.query.filter_by(stripe_client_id=data_obj['id']).first()
        logger.info (existing_user)
        if existing_user:  
            logger.info(event.id, '::Customer ', data_obj['id'], ' creado en stripe ',  " equivalente a usuario bbdd: ", existing_user.stripe_client_id)
        else : 
            return jsonify(success=False)  
    except Exception as e:
        logger.error(e)     




def webhook_invoice_payment_failed (event, data_obj):

    try:
        existing_user = User.query.filter_by(stripe_client_id=data_obj['id']).first()
        msg = EmailMessage()
        msg.set_content(f"""\
            Subject: PersonalDataIP : Stripe Payment Failure

            Dear {existing_user.username} from {existing_user.usercompany},

            We noticed that your recent payment for your subscription to personalDataIP failed. We understand that these things can happen, and we're here to help.

            Please update your payment information as soon as possible to ensure your subscription continues without interruption. You can do this by logging into your Stripe account and navigating to the 'Billing/Plan' section.

            If you have any questions or need assistance, please don't hesitate to contact us. We're here to help!

            Best regards,
                The crew of  https://www.privacy4ip.com/
            """)

        msg['Subject'] = 'Personal data IP: Payment Failure for Your Subscription'
        msg['From'] = 'privacyipapi@gmail.com'
        msg['To'] = existing_user.useremail

        server = SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login('privacyipapi@gmail.com', 'coxo daon pnup pfdm')
        server.send_message(msg)
        server.quit()

        subscription = event['data']['object']
        checkout_session = stripe.checkout.Session.retrieve(data_obj['id'])
        client_reference_id = checkout_session.customer
        if client_reference_id:            
                user1 = User.query.filter_by(stripe_client_id = client_reference_id).first()#obtengo el usuario de bbdd a partir de customer en el request
                logger.info("user en bbdd : "+str(user1)+" para client_reference_id : "+str(client_reference_id))
                if user1 :
                    user1.usage_count=int(1000000)#le pongo un millon de usage_count de forma que no podra usarlo, sea businees o corporation                       
                    flag_modified(user1, "usage_count")
                    db.session.merge(user1)
                    db.session.commit()
                    print("cambiado en bbdd usuario  "+str(user1.username)+" usage count:"+str(user1.usertype))

    except Exception as e:
            logger.error(f"An error occurred: {e}")
            return render_template('contact.html', message='An error occurred while sending the email. Please try again later.')   



def webhook_customer_subscription_past_due(event, data_obj):
     
    #a priori actuamos igual en --> event_type == 'invoice.payment_failed' or event_type == 'customer.subscription.past_due'
    webhook_invoice_payment_failed (event, data_obj) 
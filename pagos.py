
import stripe
from flask import request, jsonify
from flask import render_template, redirect, session

from app.main.models.models import Usuario
from app.run import db, url_base
#from app.main.models.models import db
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.attributes import flag_modified

#from run import create_app
#from run import csrf
#environment = 'config.DevelopmentConfig'
#app = create_app(enviroment)

from flask import Blueprint
pagos = Blueprint('pagos', __name__)



#stripe.api_key=enviroment.STRIPE_API_KEY
def set_stripe_api_key(enviroment):
    stripe.api_key = enviroment.STRIPE_API_KEY


@pagos.route('/create-checkout-session', methods=['POST'])
def create_checkout_session(enviroment):
    print("create-checkout-session form : ", request.form)
    session['chosen_price']=request.form['lookup_key']
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
            
            success_url=url_base + '/create-portal-session?session_id={CHECKOUT_SESSION_ID}',
            #success_url=enviroment.url_base + '/success.html?session_id={CHECKOUT_SESSION_ID}',
            #success_url=enviroment.url_base + '/subscripcion_exitosa?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=enviroment.url_base + '/subscripcion_cancelada',
            #client_reference_id=session['stripe_client_id'],
            customer= session['stripe_client_id'],
            metadata={'client_id': session['stripe_client_id']}
        )
        #print("checkout_session : "+str(checkout_session))
        return redirect(checkout_session.url, code=303)
    
    except Exception as e:
        print(e)
        return "Server error", 500


@pagos.route('/create-portal-session', methods=['GET','POST'])
def customer_portal(enviroment):
    session_id = request.args.get('session_id')
    #session_id =request.form.get('session_id')
    print('create-portal-session request : ',session_id)
    # For demonstration purposes, we're using the Checkout session to retrieve the customer ID.
    # Typically this is stored alongside the authenticated user in your database.    
    checkout_session = stripe.checkout.Session.retrieve(session_id)
    #print("checkout_session : "+str(checkout_session))
    # This is the URL to which the customer will be redirected after they are
    # done managing their billing with the portal.
    portalSession = stripe.billing_portal.Session.create(
        customer=checkout_session.customer,
        return_url=enviroment.url_base + '/useraccount?stripe_customer_id=' + checkout_session.customer + '&message=Succesfully Subscription' ,
    )
    return redirect(portalSession.url, code=303)



@pagos.route('/webhook', methods=['POST'])
#@csrf.exempt #csrf tiene conflicto con stripe. En su lugar usamos signature = request.headers.get('stripe-signature')
def webhook_received(enviroment):
    
   
    webhook_secret = enviroment.stripe_webhook_secret    
    request_data = json.loads(request.data)
          
    print("request_dataType: "+str(request_data['type']))
    if webhook_secret:
        # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
        signature = request.headers.get('stripe-signature')
        print("stripe-signature: "+str(signature))
        try:
            event = stripe.Webhook.construct_event(payload=request.data, sig_header=signature, secret=webhook_secret)  
             # Get the type of webhook event sent - used to check the status of PaymentIntents.
            event_type = event['type']
            data_obj=event['data']['object']  
            #print('event_type1 : ' + str(event_type))                    
        except Exception as e:
            print('Exception : ' + str(e)) 
            return jsonify(success=False)
    else:
        data = request_data['data']
        event_type = request_data['type']


   
    #print('event_type2 : ' + str(event_type))
    #print(event)    

    if event_type == 'checkout.session.completed':

        print("data_obj['id'] : ",data_obj['id'])
        checkout_session = stripe.checkout.Session.retrieve(data_obj['id'])
        print("STRIPE checkout_session : ")#,checkout_session)
        # El valor de client_reference_id se encuentra directamente en checkout_session
        #client_reference_id = checkout_session.client_reference_id
        client_reference_id = checkout_session.customer
        #price_id = checkout_session["price"]["id"]#checkout_session.line_items.data[0].price.id

        subscription_id = checkout_session['subscription']
        subscription = stripe.Subscription.retrieve(subscription_id)
        line_item = subscription['items']['data'][0]
        price_id = line_item['price']['id']

        print('🔔 checkout.session.completed : Payment succeeded! : ', client_reference_id, " /// price_id : ", price_id)
        if client_reference_id and price_id:   
            
            user1 = User.query.filter_by(stripe_client_id=client_reference_id).first()#obtengo el usuario de bbdd a partir de customer en el request
            print("user en bbdd : "+str(user1)+" para client_reference_id : "+str(client_reference_id))
            if user1 and price_id=="price_1MquVAEFh32KkLV9yaRnjDDM":#cambiar el plan de pago (usertype) en bbdd             
                    user1.usertype="Business"#stripe_subscription
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
                    print("cambiado en bbdd usuario: "+str(user1.username)+" al plan: "+str(user1.usertype))



    elif event_type =='customer.subscription.created':
        #print(event)
        #session['stripe_client_id']='cus_Nct6Cb76PRUjoC'
        '''subscription_id = data_obj["id"]
        subscription_object = stripe.Subscription.retrieve(subscription_id)
        print("subscription_object : ",subscription_object)
        session_id = stripe.Subscription.retrieve(subscription_id)["session_id"]
        # Recuperar la sesión y obtener el client_reference_id
        session = stripe.checkout.Session.retrieve(session_id)
        client_reference_id = session.client_reference_id'''        
        # El ID del precio (price) se encuentra en el objeto "price" dentro de "line_items"
        #price_id = checkout_session.line_items.data[0].price.id 
        price_id = data_obj['items']['data'][0]['plan']['id'] 
        print("price_id : "+str(price_id))
        print('Subscription created %s', event.id)
                  
        #if session['stripe_client_id']: #si existe stripe_client_id guardado en session, es pq ya he pasado por evento checkout.session.completed
        
    elif event_type == 'customer.subscription.updated':
        print('Subscription created %s', event.id)
    elif event_type == 'customer.subscription.deleted':
        # handle subscription canceled automatically based
        # upon your subscription settings. Or if the user cancels it.
        print('Subscription canceled: %s', event.id)
    elif event_type == 'customer.created':
        print("customer.created ID : ",data_obj['id'])
        existing_user = User.query.filter_by(stripe_client_id=data_obj['id'] ).first()
        if existing_user: 
            print(event.id, '::Customer ', data_obj['id'], ' creado en stripe ',  " equivalente a ", existing_user.stripe_client_id)
        else : 
           return jsonify(success=False)  
    return jsonify({'status': 'success'}, 200)




@pagos.route('/subscripcion_cancelada')
def subscripcion_cancelada(enviroment):
    return render_template('cancel.html')   


@pagos.route('/subscripcion_exitosa')
def subscripcion_exitosa(enviroment):    
    checkout_session_id = request.args.get('session_id')    
    return render_template('success.html', session_id=checkout_session_id)
#=====================================================================================================================================================
#=====================================================================================================================================================
#=====================================================================================================================================================
 
#stripe.api_key = configuracion.STRIPE_API_KEY

 #=====================================================================================================================================================
   
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():

    #price_id = request.form.get('lookup_key')
    price_id = request.form['lookup_key']
    session['price_id']=price_id    
    print ("price_id : "+str(session['price_id']))
    
    try:
        '''prices = stripe.Price.list(
            lookup_keys=[request.form['lookup_key']],
            expand=['data.product']
        )
        print ("prices : "+str(prices))'''
        
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    #'price': prices.data[0].id,
                    'price': price_id,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url='http://127.0.0.1:5000/subscripcion_exitosa?session_id={CHECKOUT_SESSION_ID}',
            cancel_url='http://127.0.0.1:5000/subscripcion_cancelada',            
            
            #success_url=YOUR_DOMAIN +'/success.html?session_id={CHECKOUT_SESSION_ID}',
            #cancel_url=YOUR_DOMAIN + '/cancel.html',
        )
        print ("checkout_session : "+str(checkout_session))
        return redirect(checkout_session.url, code=303)

    except Exception as e:
        print(e)
        return "Server error", 500



@app.route('/create-portal-session', methods=['POST'])
def customer_portal():
    # For demonstration purposes, we're using the Checkout session to retrieve the customer ID.
    # Typically this is stored alongside the authenticated user in your database.
    
    #checkout_session_id = request.form.get('session_id')
    checkout_session_id = session['checkout_session_id']
    #print("checkout_session_id : "+ str(checkout_session_id))
    checkout_session = stripe.checkout.Session.retrieve(checkout_session_id)

    # This is the URL to which the customer will be redirected after they are
    # done managing their billing with the portal.
    return_url = YOUR_DOMAIN

    portalSession = stripe.billing_portal.Session.create(
        customer=checkout_session.customer,
        return_url=return_url,
    )
        
    return redirect(portalSession.url, code=303)



@app.route('/webhook', methods=['GET', 'POST'])
def webhook_received():
    # Replace this endpoint secret with your endpoint's unique secret
    # If you are testing with the CLI, find the secret by running 'stripe listen'
    # If you are using an endpoint defined with the API or dashboard, look in your webhook settings
    # at https://dashboard.stripe.com/webhooks
    
    #webhook_secret = configuracion.stripe_webhook_secret
    webhook_secret = enviroment.stripe_webhook_secret
    request_data = json.loads(request.data)
    print ("request_data : "+str(request_data))
    if webhook_secret:
        # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
        signature = request.headers.get('stripe-signature')
        try:
            event = stripe.Webhook.construct_event(payload=request.data, sig_header=signature, secret=webhook_secret)
            data = event['data']
        except Exception as e:
            return e
        # Get the type of webhook event sent - used to check the status of PaymentIntents.
        event_type = event['type']
    else:
        data = request_data['data']
        event_type = request_data['type']
    data_object = data['object']

    print('event : ' + event_type)

    if event['type'] == 'checkout.session.completed':
        checkout_session = event['data']['object']
        customer_id = checkout_session['customer']
        product_id = checkout_session['display_items'][0]['plan']['id']

        # Actualiza el registro de usuario correspondiente con el tipo de producto
        user = User.query.filter_by(customer_id=customer_id).first()
        if user:
            if product_id == 'Free':
                user.usertype = 'Free'
            elif product_id == 'Business':
                user.usertype = 'Business'
            elif product_id == 'Corporation':
                user.usertype = 'Corporation'
            db.session.commit()
        else:
            # Maneja el caso en que no se encuentre un usuario con el customer_id
            print('Subscription canceled: %s', event.id)
        # handle subscription canceled automatically based
        # upon your subscription settings. Or if the user cancels it.
            

    return jsonify({'status': 'success'})   


#=====================================================================================================================================================



@app.route('/subscripcion_exitosa')
def subscripcion_exitosa():
    
    session['checkout_session_id'] = request.args.get('session_id')   
    for key, value in session.items():
              print(f'{key}: {value}')
            
    if 'username' in session:    
        user1 = User.query.filter_by(username=session['username']).first()#obtengo el usuario de bbdd de usuario en session
    if user1 :#cambiar el plan de pago (usertype) en bbdd 
        if session['price_id']=="price_1Ml7a4Dpa8n85JEHwaJ52Svz":
            user1.usertype="Business"#stripe_subscription
            db.session.commit()
        session['userplan'] = user1.usertype
        
    else:#no existe usuario actual en bbdd
        return redirect('/subscripcion_cancelada')
    return render_template('success.html')
 

 #=====================================================================================================================================================


 
@app.route('/subscripcion_cancelada')
def subscripcion_cancelada():
    return render_template('cancel.html')   


 #=====================================================================================================================================================
# Ruta para configurar el webhook de Stripe
@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    stripe_payload = request
    print("stripe_payload : "+str(stripe_payload))     
    configure_stripe_webhook(request)
    return '', 200
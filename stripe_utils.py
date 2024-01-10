import stripe
import configuracion
from flask import request
import json


# Manejar el evento de suscripción exitosa
def handle_subscription_created_event(event):
    subscription = event['data']['object']
    plan_id = subscription['plan']['id']
    
    print(f"El cliente seleccionó el plan con ID {plan_id}")

# Configurar el webhook de Stripe para recibir notificaciones de eventos
def configure_stripe_webhook(request):
        event = None
        # Obtener el cuerpo de la solicitud webhook
        payload = request.get_data()        
        # Generar una firma de la solicitud webhook
        sig_header = request.headers.get('Stripe-Signature', None)
        print(payload)
        try:
            event = stripe.Event.construct_from(json.loads(payload), configuracion.STRIPE_API_KEY, configuracion.stripe_webhook_secret)
        
        except ValueError:
            print("Invalid payload")
            return "Invalid payload", 400
        except stripe.error.SignatureVerificationError:
            print("Invalid signature")
            return "Invalid signature", 400

        # Procesar el evento de la solicitud webhook
        #print(event)
        if event['type'] == 'customer.subscription.created':
                handle_subscription_created_event(event)

        return redirect(url_for('user_account'))

    
        '''print (request.headers)
        endpoint_secret = config.stripe_webhook_secret
        stripe.Webhook.construct_event(request.data, request.headers.get('Stripe-Signature'), endpoint_secret)
        event = stripe.Event.construct_from(json.loads(request.data), stripe.api_key)
        if event['type'] == 'customer.subscription.created':
            handle_subscription_created_event(event)'''

from flask_mail import Message, Mail

def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Mail.send(msg)
    
    
    
    #msg = Message('Mensaje desde tu sitio web', sender='<tu_correo>@gmail.com', recipients=['<destinatario>@gmail.com'])
    #msg.body = f"Nombre: {nombre}\nCorreo electrónico: {correo}\nMensaje:\n{mensaje}"
    #mail.send(msg)
    
    return 'Message sent successfully! We will contact you shortly'    
from django.core.mail import EmailMessage



class Utils():
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email='abc@x.com',
            to=[data['to_email']]
        )
        email.send()
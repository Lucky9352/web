from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
from smtplib import SMTP_SSL
import ssl

class Command(BaseCommand):
    help = 'Test SMTP email configuration with SSL'

    def handle(self, *args, **kwargs):
        self.stdout.write('Testing SMTP configuration with SSL...')
        
        try:
            # Create SSL context
            self.stdout.write('1. Creating SSL context...')
            context = ssl.create_default_context()
            
            # Connect with SSL from the start
            self.stdout.write('2. Connecting to SMTP server with SSL...')
            with SMTP_SSL(settings.EMAIL_HOST, settings.EMAIL_PORT, context=context) as server:
                self.stdout.write('3. Attempting login...')
                server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
                
                self.stdout.write('4. Sending test email...')
                subject = 'SMTP Test Email'
                message = 'This is a test email to verify SMTP settings.'
                from_email = settings.DEFAULT_FROM_EMAIL
                recipient_list = [settings.EMAIL_HOST_USER]
                
                send_mail(
                    subject,
                    message,
                    from_email,
                    recipient_list,
                    fail_silently=False,
                )
                
            self.stdout.write(self.style.SUCCESS('Email configuration test completed successfully!'))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))
            raise

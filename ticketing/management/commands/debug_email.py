from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
import time
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Debug email sending with detailed logging'

    def add_arguments(self, parser):
        parser.add_argument('--to', type=str, help='Email address to send test email to')
        parser.add_argument('--retries', type=int, default=3, help='Number of retries')

    def handle(self, *args, **options):
        to_email = options.get('to') or settings.EMAIL_HOST_USER
        retries = options.get('retries')

        self.stdout.write(self.style.NOTICE('\nEmail Configuration:'))
        self.stdout.write(f'From: {settings.DEFAULT_FROM_EMAIL}')
        self.stdout.write(f'SMTP Host: {settings.EMAIL_HOST}')
        self.stdout.write(f'SMTP Port: {settings.EMAIL_PORT}')
        self.stdout.write(f'Use TLS: {settings.EMAIL_USE_TLS}')
        self.stdout.write(f'Use SSL: {settings.EMAIL_USE_SSL}')
        self.stdout.write(f'Timeout: {getattr(settings, "EMAIL_TIMEOUT", "Not set")}')

        for attempt in range(retries):
            try:
                self.stdout.write(f'\nAttempt {attempt + 1} of {retries}:')
                
                send_mail(
                    subject='Debug Test Email',
                    message='This is a test email to debug the email sending functionality.',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[to_email],
                    fail_silently=False,
                )
                
                self.stdout.write(self.style.SUCCESS(f'Email sent successfully to {to_email}'))
                return
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Attempt {attempt + 1} failed: {str(e)}'))
                if attempt < retries - 1:
                    self.stdout.write('Waiting before retry...')
                    time.sleep(2 ** attempt)  # Exponential backoff
                    
        self.stdout.write(self.style.ERROR(f'\nFailed to send email after {retries} attempts'))

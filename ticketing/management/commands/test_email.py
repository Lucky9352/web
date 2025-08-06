import time
import socket
import logging
from django.core.management.base import BaseCommand
from django.conf import settings
from django.core.mail import send_mail, get_connection
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Test email configuration with comprehensive diagnostics'

    def add_arguments(self, parser):
        parser.add_argument('--to', type=str, help='Email address to send test email to')
        parser.add_argument('--retries', type=int, default=3, help='Number of retries')
        parser.add_argument('--html', action='store_true', help='Send HTML email')
        parser.add_argument('--direct', action='store_true', help='Use direct connection instead of backend')
        parser.add_argument('--utils', action='store_true', help='Use utility function instead of direct sending')

    def handle(self, *args, **options):
        to_email = options.get('to') or settings.EMAIL_HOST_USER
        retries = options.get('retries', 3)
        use_html = options.get('html', False)
        use_direct = options.get('direct', False)
        use_utils = options.get('utils', False)

        # Display current email configuration
        self.stdout.write(self.style.NOTICE('\n=== Email Configuration ==='))
        self.stdout.write(f'Backend: {settings.EMAIL_BACKEND}')
        self.stdout.write(f'From: {settings.DEFAULT_FROM_EMAIL}')
        self.stdout.write(f'SMTP Host: {settings.EMAIL_HOST}')
        self.stdout.write(f'SMTP Port: {settings.EMAIL_PORT}')
        self.stdout.write(f'Use TLS: {settings.EMAIL_USE_TLS}')
        self.stdout.write(f'Use SSL: {getattr(settings, "EMAIL_USE_SSL", False)}')
        self.stdout.write(f'Timeout: {getattr(settings, "EMAIL_TIMEOUT", "Not set")}')
        
        # Display custom email settings
        self.stdout.write(self.style.NOTICE('\n=== Custom Email Settings ==='))
        self.stdout.write(f'Max Retries: {getattr(settings, "CUSTOM_EMAIL_MAX_RETRIES", 3)}')
        self.stdout.write(f'Retry Delay: {getattr(settings, "CUSTOM_EMAIL_RETRY_DELAY", 2)}')
        self.stdout.write(f'Debug Mode: {getattr(settings, "CUSTOM_EMAIL_DEBUG", False)}')

        # Check if EMAIL_HOST_PASSWORD is set
        if not settings.EMAIL_HOST_PASSWORD:
            self.stdout.write(self.style.ERROR('\nWARNING: EMAIL_HOST_PASSWORD is not set!'))
            self.stdout.write('Make sure your .env file contains the EMAIL_HOST_PASSWORD variable')

        # Network connectivity test
        self.stdout.write(self.style.NOTICE('\n=== Network Connectivity Test ==='))
        try:
            self.stdout.write(f'Testing connection to {settings.EMAIL_HOST}:{settings.EMAIL_PORT}...')
            socket_type = socket.SOCK_STREAM
            sock = socket.socket(socket.AF_INET, socket_type)
            sock.settimeout(10)
            sock.connect((settings.EMAIL_HOST, settings.EMAIL_PORT))
            sock.close()
            self.stdout.write(self.style.SUCCESS(f'Successfully connected to {settings.EMAIL_HOST}:{settings.EMAIL_PORT}'))
        except socket.timeout:
            self.stdout.write(self.style.ERROR(f'Connection timeout to {settings.EMAIL_HOST}:{settings.EMAIL_PORT}'))
        except socket.error as e:
            self.stdout.write(self.style.ERROR(f'Connection error: {e}'))

        # Prepare email content
        subject = 'Test Email from Tapnex'
        plain_message = 'This is a test email to verify the email sending functionality is working properly.'
        html_content = None
        
        if use_html:
            html_content = f'''
            <html>
                <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4;">
                    <div style="max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
                        <h1 style="color: #0056b3;">Test Email</h1>
                        <p>This is a test email to verify the email sending functionality is working properly.</p>
                        <p>Date and time: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                </body>
            </html>
            '''

        # Try different methods based on options
        if use_utils:
            self.stdout.write(self.style.NOTICE('\n=== Using Utility Function ==='))
            from ticketing.utils import send_email_with_retry
            
            email_sent = send_email_with_retry(
                subject=subject,
                message=plain_message,
                html_message=html_content if use_html else None,
                recipient_list=[to_email],
                max_retries=retries
            )
            
            if email_sent:
                self.stdout.write(self.style.SUCCESS(f'Email sent successfully to {to_email}'))
            else:
                self.stdout.write(self.style.ERROR('Email sending failed using utility function'))
            
            return
            
        # Send email with or without direct connection
        for attempt in range(1, retries + 1):
            self.stdout.write(self.style.NOTICE(f'\n=== Email Sending Test - Attempt {attempt}/{retries} ==='))
            
            try:
                if use_direct:
                    self.stdout.write('Using direct connection...')
                    connection = get_connection(fail_silently=False)
                    self.stdout.write('Opening connection...')
                    connection.open()
                    self.stdout.write('Connection opened, sending email...')
                    
                    send_mail(
                        subject=subject,
                        message=plain_message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[to_email],
                        html_message=html_content,
                        connection=connection,
                        fail_silently=False,
                    )
                    
                    self.stdout.write('Closing connection...')
                    connection.close()
                else:
                    self.stdout.write('Using configured backend...')
                    send_mail(
                        subject=subject,
                        message=plain_message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[to_email],
                        html_message=html_content,
                        fail_silently=False,
                    )
                    
                self.stdout.write(self.style.SUCCESS(f'Email sent successfully to {to_email}'))
                return
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Error sending email: {type(e).__name__}: {str(e)}'))
                
                if attempt < retries:
                    delay = 2 * attempt
                    self.stdout.write(f'Retrying in {delay} seconds...')
                    time.sleep(delay)
                else:
                    self.stdout.write(self.style.ERROR(f'Failed to send email after {retries} attempts'))

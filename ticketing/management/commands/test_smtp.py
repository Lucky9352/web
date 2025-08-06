from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
from smtplib import SMTP, SMTPHeloError, SMTPException
import ssl
import socket

class Command(BaseCommand):
    help = 'Test SMTP email configuration with detailed EHLO/HELO validation'

    def handle(self, *args, **kwargs):
        self.stdout.write('Testing SMTP configuration with detailed handshake...')
        
        try:
            # Get local hostname for EHLO
            local_hostname = socket.gethostname().split('.')[0]  # Get first part of hostname
            self.stdout.write(f'Using hostname for EHLO: {local_hostname}')
            
            # First test SMTP connection with explicit error handling
            self.stdout.write('\n1. Establishing SMTP connection...')
            smtp = SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT, local_hostname=local_hostname)
            
            try:
                self.stdout.write('\n2. Sending EHLO command...')
                ehlo_response = smtp.ehlo()
                if ehlo_response[0] == 250:
                    self.stdout.write(self.style.SUCCESS(f'EHLO successful. Server response:\n{ehlo_response[1].decode()}'))
                else:
                    self.stdout.write(self.style.WARNING(f'Unexpected EHLO response code: {ehlo_response[0]}'))
                    
                    # Try HELO as fallback
                    self.stdout.write('\nAttempting HELO as fallback...')
                    helo_response = smtp.helo()
                    if helo_response[0] == 250:
                        self.stdout.write(self.style.SUCCESS(f'HELO successful. Server response:\n{helo_response[1].decode()}'))
                    else:
                        raise SMTPHeloError(helo_response[0], helo_response[1])
            except SMTPHeloError as e:
                self.stdout.write(self.style.ERROR(f'EHLO/HELO error: {str(e)}'))
                raise
                
            if settings.EMAIL_USE_TLS:
                self.stdout.write('\n3. Starting TLS...')
                context = ssl.create_default_context()
                tls_response = smtp.starttls(context=context)
                self.stdout.write(self.style.SUCCESS(f'TLS established. Response: {tls_response}'))
                
                # Must send EHLO again after STARTTLS
                self.stdout.write('\n4. Sending EHLO again after TLS...')
                ehlo_response = smtp.ehlo()
                self.stdout.write(self.style.SUCCESS(f'Post-TLS EHLO response:\n{ehlo_response[1].decode()}'))
            
            self.stdout.write('\n5. Attempting login...')
            smtp.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            
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
            
            self.stdout.write('\n6. Testing email send...')
            send_mail(
                'SMTP Test - EHLO Validation',
                'This test email confirms proper SMTP handshake with valid EHLO/HELO.',
                settings.DEFAULT_FROM_EMAIL,
                [settings.EMAIL_HOST_USER],
                fail_silently=False,
            )
            
            self.stdout.write('\n7. Closing connection...')
            smtp.quit()
            self.stdout.write(self.style.SUCCESS('\nSMTP test completed successfully! All handshake steps passed.'))
            
        except SMTPHeloError as e:
            self.stdout.write(self.style.ERROR(f'\nEHLO/HELO command failed: {str(e)}'))
            raise
        except socket.gaierror as e:
            self.stdout.write(self.style.ERROR(f'\nHostname resolution error: {str(e)}'))
            raise
        except SMTPException as e:
            self.stdout.write(self.style.ERROR(f'\nSMTP error: {str(e)}'))
            raise
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'\nUnexpected error: {str(e)}'))
            raise

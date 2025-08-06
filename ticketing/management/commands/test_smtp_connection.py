from django.core.management.base import BaseCommand
from django.conf import settings
from smtplib import SMTP, SMTP_SSL, SMTPHeloError, SMTPException
import ssl
import socket
import sys

class Command(BaseCommand):
    help = 'Test SMTP connection with detailed debugging for EHLO/HELO'

    def add_arguments(self, parser):
        parser.add_argument('--use-ssl', action='store_true', help='Use SMTP_SSL instead of STARTTLS')
        parser.add_argument('--debug-level', type=int, default=1, help='SMTP debug level (0-2)')
        parser.add_argument('--hostname', type=str, help='Custom hostname for EHLO/HELO')

    def handle(self, *args, **options):
        debug_level = options['debug_level']
        use_ssl = options['use_ssl']
        custom_hostname = options.get('hostname') or socket.getfqdn()

        # Strip any potentially problematic characters from hostname
        safe_hostname = ''.join(c for c in custom_hostname if c.isalnum() or c in '.-')
        if not safe_hostname:
            safe_hostname = 'localhost'

        # Always use Gmail SMTP settings
        host = 'smtp.gmail.com'
        port = 465 if use_ssl else 587

        self.stdout.write(self.style.NOTICE(f'\nSMTP Test Configuration:'))
        self.stdout.write(f'Host: {host}')
        self.stdout.write(f'Port: {port}')
        self.stdout.write(f'Use SSL: {use_ssl}')
        self.stdout.write(f'Debug Level: {debug_level}')
        self.stdout.write(f'EHLO Hostname: {safe_hostname}')

        try:
            if use_ssl:
                self.stdout.write('\n1. Creating SSL context...')
                context = ssl.create_default_context()
                
                self.stdout.write('2. Connecting with SMTP_SSL...')
                smtp = SMTP_SSL(host, port, local_hostname=safe_hostname, context=context)
            else:
                self.stdout.write('\n1. Creating plain SMTP connection...')
                smtp = SMTP(host, port, local_hostname=safe_hostname)

            # Enable debug output
            smtp.set_debuglevel(debug_level)

            try:
                self.stdout.write('\n2. Sending EHLO...')
                code, message = smtp.ehlo()
                if code == 250:
                    self.stdout.write(self.style.SUCCESS(
                        f'EHLO successful (250)\nServer response:\n{message.decode()}'
                    ))
                else:
                    self.stdout.write(self.style.WARNING(
                        f'Unexpected EHLO response: {code}\nTrying HELO...'
                    ))
                    code, message = smtp.helo()
                    if code == 250:
                        self.stdout.write(self.style.SUCCESS(
                            f'HELO successful (250)\nServer response:\n{message.decode()}'
                        ))
                    else:
                        raise SMTPHeloError(code, message.decode())

            except SMTPHeloError as e:
                self.stdout.write(self.style.ERROR(f'EHLO/HELO failed: {str(e)}'))
                raise

            if not use_ssl:
                self.stdout.write('\n3. Starting TLS...')
                context = ssl.create_default_context()
                try:
                    code, message = smtp.starttls(context=context)
                    self.stdout.write(self.style.SUCCESS(
                        f'TLS started successfully ({code})\nServer response: {message.decode()}'
                    ))

                    # Must EHLO again after STARTTLS
                    self.stdout.write('\n4. Sending post-TLS EHLO...')
                    code, message = smtp.ehlo()
                    if code != 250:
                        raise SMTPHeloError(code, message.decode())
                    self.stdout.write(self.style.SUCCESS(
                        f'Post-TLS EHLO successful\nServer response:\n{message.decode()}'
                    ))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'TLS startup failed: {str(e)}'))
                    raise

            self.stdout.write('\n5. Attempting login...')
            try:
                smtp.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
                self.stdout.write(self.style.SUCCESS('Login successful!'))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Login failed: {str(e)}'))
                raise

            self.stdout.write('\n6. Closing connection...')
            smtp.quit()
            self.stdout.write(self.style.SUCCESS('\nSMTP test completed successfully!'))

        except socket.gaierror as e:
            self.stdout.write(self.style.ERROR(f'\nHostname resolution error: {str(e)}'))
            sys.exit(1)
        except ConnectionRefusedError as e:
            self.stdout.write(self.style.ERROR(
                f'\nConnection refused! Check if:\n'
                f'1. Port {settings.EMAIL_PORT} is correct\n'
                f'2. No firewall is blocking the connection\n'
                f'3. The SMTP server is accepting connections\n'
                f'Error: {str(e)}'
            ))
            sys.exit(1)
        except SMTPException as e:
            self.stdout.write(self.style.ERROR(f'\nSMTP error: {str(e)}'))
            sys.exit(1)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'\nUnexpected error: {str(e)}'))
            sys.exit(1)

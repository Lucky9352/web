from django.core.mail.backends.smtp import EmailBackend
import logging
import socket
import time
import ssl
import smtplib

logger = logging.getLogger(__name__)

class CustomEmailBackend(EmailBackend):
    
    def __init__(self, *args, **kwargs):
        self.debug = kwargs.pop('debug', False)
        self.max_retries = kwargs.pop('max_retries', 3)
        self.retry_delay = kwargs.pop('retry_delay', 2)  # Increased default delay
        self.connection_timeout = kwargs.pop('timeout', 60)  # Longer timeout
        self.hostname = socket.gethostname()
        logger.info(f"CustomEmailBackend initialized with hostname: {self.hostname}")
        super().__init__(*args, **kwargs)
    
    def open(self):
        """
        Ensures the connection is open, with retries on failure.
        """
        if self.connection:
            # Check if connection is still alive
            try:
                status = self.connection.noop()[0]
                if status == 250:
                    logger.info("Reusing existing SMTP connection")
                    return True
            except (smtplib.SMTPServerDisconnected, smtplib.SMTPResponseException, socket.error) as e:
                logger.info(f"Existing connection no longer valid: {str(e)}")
                self.close()
            except Exception as e:
                logger.info(f"Unexpected error with existing connection: {str(e)}")
                self.close()
        
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(f"Attempting to open SMTP connection (attempt {attempt}/{self.max_retries})")
                
                # Create the connection manually for more control
                if not self.connection:
                    connection_class = smtplib.SMTP_SSL if self.use_ssl else smtplib.SMTP
                    self.connection = connection_class(
                        self.host,
                        self.port,
                        local_hostname=self.hostname,
                        timeout=self.connection_timeout
                    )
                    
                    # Set debugging level
                    if hasattr(self, 'debug') and self.debug:
                        self.connection.set_debuglevel(1)
                    
                    # TLS connection
                    if not self.use_ssl and self.use_tls:
                        logger.debug("Initiating TLS connection")
                        self.connection.ehlo()
                        self.connection.starttls(context=ssl.create_default_context())
                        self.connection.ehlo()
                    
                    # Authentication
                    if self.username and self.password:
                        logger.debug("Authenticating with SMTP server")
                        try:
                            self.connection.login(self.username, self.password)
                        except smtplib.SMTPAuthenticationError as e:
                            logger.error(f"SMTP Authentication error: {e}")
                            self.close()
                            raise
                
                # Verify connection with a NOOP command
                status = self.connection.noop()[0]
                if status == 250:
                    logger.info(f"SMTP connection established successfully on attempt {attempt}")
                    return True
                else:
                    logger.warning(f"Connection established but NOOP returned status {status}")
                    self.close()
            except (socket.timeout, ConnectionRefusedError) as e:
                logger.warning(f"Connection timeout/refused on attempt {attempt}/{self.max_retries}: {str(e)}")
                self.close()
            except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError) as e:
                logger.warning(f"SMTP connection error on attempt {attempt}/{self.max_retries}: {str(e)}")
                self.close()
            except ssl.SSLError as e:
                logger.warning(f"SSL error on attempt {attempt}/{self.max_retries}: {str(e)}")
                self.close()
            except Exception as e:
                logger.warning(f"Failed to open SMTP connection on attempt {attempt}/{self.max_retries}: {type(e).__name__}: {str(e)}")
                self.close()
            
            if attempt < self.max_retries:
                delay = self.retry_delay * attempt  # Exponential backoff
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                logger.error(f"Failed to establish SMTP connection after {self.max_retries} attempts")
        
        return False
    
    def send_messages(self, email_messages):
        """
        Sends one or more EmailMessage objects and returns the number of email
        messages sent.
        """
        if not email_messages:
            return 0
            
        num_sent = 0
        connection_open = False
        
        try:
            connection_open = self.open()
            if not connection_open:
                logger.error("Failed to establish connection")
                return 0
                
            for message in email_messages:
                # Try to send each message, with retry logic
                for msg_attempt in range(1, self.max_retries + 1):
                    try:
                        # Check if connection is still alive
                        if not self.connection:
                            logger.warning("Connection lost, attempting to reopen")
                            connection_open = self.open()
                            if not connection_open:
                                logger.error("Failed to reestablish connection")
                                break
                        
                        # Try to verify connection is still working
                        try:
                            self.connection.noop()
                        except (smtplib.SMTPServerDisconnected, socket.error):
                            logger.warning("Connection appears dead, reopening")
                            self.close()
                            connection_open = self.open()
                            if not connection_open:
                                logger.error("Failed to reestablish connection")
                                break
                        
                        # Send the message
                        sent = self._send(message)
                        if sent:
                            num_sent += 1
                            logger.info(f"Email sent successfully to {', '.join(message.to)}")
                            break  # Successfully sent this message, move to next one
                        else:
                            logger.warning(f"Failed to send email to {', '.join(message.to)}")
                    
                    except smtplib.SMTPSenderRefused as e:
                        logger.error(f"SMTP refused sender: {e}")
                        # No point retrying with same sender
                        break
                    
                    except smtplib.SMTPRecipientsRefused as e:
                        logger.error(f"SMTP refused recipients: {e}")
                        # No point retrying with same recipients
                        break
                    
                    except (smtplib.SMTPServerDisconnected, socket.timeout, ssl.SSLError) as e:
                        logger.warning(f"Connection error on attempt {msg_attempt}: {str(e)}")
                        self.close()
                        if msg_attempt < self.max_retries:
                            logger.info(f"Reopening connection and retrying message")
                            connection_open = self.open()
                        else:
                            logger.error(f"Failed to send message after {self.max_retries} attempts")
                    
                    except Exception as e:
                        logger.error(f"Error sending message to {', '.join(message.to)}: {type(e).__name__}: {str(e)}")
                        if msg_attempt < self.max_retries:
                            # For other errors, wait before retrying
                            time.sleep(self.retry_delay)
                        else:
                            logger.error(f"Failed to send message after {self.max_retries} attempts")
            
            return num_sent
        except Exception as e:
            logger.error(f"Exception during send_messages: {type(e).__name__}: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return num_sent
        finally:
            if connection_open:
                try:
                    self.close()
                except Exception as e:
                    logger.error(f"Error closing connection: {str(e)}")
                    pass

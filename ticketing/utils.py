import logging
from django.conf import settings
import csv
import io
import secrets
import string
import time
from django.utils import timezone
from .models import Ticket, TicketType, User
import uuid
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)

def generate_otp(length=6):
    """Generates a secure OTP."""
    characters = string.digits
    otp = ''.join(secrets.choice(characters) for i in range(length))
    return otp

def send_otp_email(email, otp):
    """Sends the OTP to the user's email address."""
    subject = 'Verify your email for Tapnex'
    html_message = render_to_string('core/email/otp_email.html', {'otp': otp})
    plain_message = strip_tags(html_message)
    from_email = settings.DEFAULT_FROM_EMAIL
    to = email
    
    # Use the send_email_with_retry function for better reliability
    return send_email_with_retry(
        subject=subject,
        message=plain_message,
        html_message=html_message,
        from_email=from_email,
        recipient_list=[to]
    )

def send_email_with_retry(subject, message, recipient_list, html_message=None, from_email=None, max_retries=3, delay=1):
    """
    Send email with retry mechanism using Django's standard email backend.
    """
    if from_email is None:
        from_email = settings.DEFAULT_FROM_EMAIL
        
    # Use custom settings if available
    max_retries = getattr(settings, 'CUSTOM_EMAIL_MAX_RETRIES', max_retries)
    initial_delay = getattr(settings, 'CUSTOM_EMAIL_RETRY_DELAY', delay)
    
    logger.info(f"Preparing to send email to {recipient_list}")
    logger.info(f"Email subject: {subject}")
    
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Attempting to send email (attempt {attempt}/{max_retries})")
            
            send_mail(
                subject=subject,
                message=message,
                from_email=from_email,
                recipient_list=recipient_list,
                html_message=html_message,
                fail_silently=False,
            )
            
            logger.info(f"Email sent successfully on attempt {attempt}")
            return True
            
        except Exception as e:
            logger.error(f"Email sending failed on attempt {attempt}/{max_retries}: {type(e).__name__}: {str(e)}")
            
            if attempt < max_retries:
                current_delay = initial_delay * attempt  # Exponential backoff
                logger.info(f"Retrying in {current_delay} seconds...")
                time.sleep(current_delay)
            else:
                logger.error(f"Failed to send email after {max_retries} attempts")
                
    return False

def handle_event_csv_upload(csv_file, user):
    """
    Handle CSV file upload for event creation
    No character limits or restrictions on data
    """
    try:
        from datetime import datetime
        from decimal import Decimal
        from .models import Event, TicketType
        
        # Read the CSV file - support potentially large files
        decoded_file = csv_file.read().decode('utf-8')
        io_string = io.StringIO(decoded_file)
        reader = csv.DictReader(io_string)
        
        rows = list(reader)
        if not rows:
            return False, "No data found in CSV file", None
        
        # Process the first event (we'll support one event per CSV file)
        row = rows[0]
        
        # Create Event with minimal validation
        try:
            event = Event(
                title=row.get('title') or 'Untitled Event',
                description=row.get('description') or '',
                event_type=row.get('event_type') or 'General',
                short_description=row.get('short_description', ''),
                organizer=user
            )
            
            # Handle date/time fields with better error checking
            try:
                if row.get('date'):
                    event.date = datetime.strptime(row.get('date'), '%Y-%m-%d').date()
                else:
                    # Default to current date if not provided
                    event.date = datetime.now().date()
            except ValueError:
                logger.warning(f"Invalid date format: {row.get('date')}, using current date")
                event.date = datetime.now().date()
                
            try:
                if row.get('time'):
                    event.time = datetime.strptime(row.get('time'), '%H:%M').time()
                else:
                    # Default to current time if not provided
                    event.time = datetime.now().time()
            except ValueError:
                logger.warning(f"Invalid time format: {row.get('time')}, using current time")
                event.time = datetime.now().time()
                
            # Handle optional date/time fields
            try:
                if row.get('end_date'):
                    event.end_date = datetime.strptime(row.get('end_date'), '%Y-%m-%d').date()
            except ValueError:
                logger.warning(f"Invalid end_date format: {row.get('end_date')}, ignoring")
                
            try:
                if row.get('end_time'):
                    event.end_time = datetime.strptime(row.get('end_time'), '%H:%M').time()
            except ValueError:
                logger.warning(f"Invalid end_time format: {row.get('end_time')}, ignoring")
                
            # Handle venue information
            event.venue = row.get('venue', 'TBD')
            event.venue_address = row.get('venue_address', '')
            event.venue_map_link = row.get('venue_map_link', '')
            
            # Handle capacity with error checking
            try:
                if row.get('capacity'):
                    event.capacity = int(row.get('capacity'))
                else:
                    event.capacity = 100  # Default capacity
            except ValueError:
                logger.warning(f"Invalid capacity: {row.get('capacity')}, using default 100")
                event.capacity = 100
                
            # Handle registration deadline with error checking
            try:
                if row.get('registration_deadline'):
                    event.registration_deadline = datetime.strptime(row.get('registration_deadline'), '%Y-%m-%d %H:%M')
            except ValueError:
                logger.warning(f"Invalid registration_deadline format: {row.get('registration_deadline')}, ignoring")
                
            # Handle other fields
            event.venue_terms = row.get('venue_terms', '')
            event.event_terms = row.get('event_terms', '')
            event.restrictions = row.get('restrictions', '')
            event.status = row.get('status', 'DRAFT')
            event.featured = row.get('featured', '').lower() == 'true'
            
            # Save the event to get an ID
            event.save()
            logger.info(f"Created event: {event.title} (ID: {event.id})")
            
            # Process ticket types
            ticket_types_created = 0
            for i in range(1, 5):  # Up to 4 ticket types
                type_name = row.get(f'ticket_type_{i}')
                if type_name and type_name.strip():
                    try:
                        # Default values if not provided or invalid
                        price_str = row.get(f'ticket_price_{i}', '0')
                        price = Decimal(price_str) if price_str else Decimal('0')
                        
                        quantity_str = row.get(f'ticket_quantity_{i}', '0')
                        quantity = int(quantity_str) if quantity_str else 0
                        
                        description = row.get(f'ticket_description_{i}', '')
                        
                        attendees_str = row.get(f'ticket_attendees_per_ticket_{i}', '1')
                        attendees_per_ticket = int(attendees_str) if attendees_str else 1
                        
                        TicketType.objects.create(
                            event=event,
                            type_name=type_name,
                            price=price,
                            quantity=quantity,
                            description=description,
                            attendees_per_ticket=attendees_per_ticket
                        )
                        ticket_types_created += 1
                        logger.info(f"Created ticket type: {type_name} for event {event.title}")
                    except (ValueError, TypeError, Decimal.InvalidOperation) as e:
                        logger.error(f"Error creating ticket type {i}: {str(e)}")
            
            if ticket_types_created == 0:
                # Create a default ticket type if none were created
                TicketType.objects.create(
                    event=event,
                    type_name="General Admission",
                    price=Decimal('0.00'),
                    quantity=event.capacity,
                    description="Default ticket type",
                    attendees_per_ticket=1
                )
                logger.info(f"Created default ticket type for event {event.title}")
                
            return True, "Event created successfully from CSV", event.id
        except Exception as e:
            logger.error(f"Error creating event: {str(e)}")
            return False, f"Error creating event: {str(e)}", None
    except Exception as e:
        logger.error(f"Error processing CSV: {str(e)}")
        return False, f"Error processing CSV: {str(e)}", None

def generate_sample_csv():
    """
    Generate a sample CSV for event creation
    """
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'title', 'description', 'event_type', 'short_description', 
        'date', 'time', 'end_date', 'end_time', 
        'venue', 'venue_address', 'venue_map_link', 'capacity', 
        'registration_deadline', 'venue_terms', 'event_terms', 'restrictions',
        'status', 'featured',
        'ticket_type_1', 'ticket_price_1', 'ticket_quantity_1', 'ticket_description_1', 'ticket_attendees_per_ticket_1',
        'ticket_type_2', 'ticket_price_2', 'ticket_quantity_2', 'ticket_description_2', 'ticket_attendees_per_ticket_2',
        'ticket_type_3', 'ticket_price_3', 'ticket_quantity_3', 'ticket_description_3', 'ticket_attendees_per_ticket_3',
        'ticket_type_4', 'ticket_price_4', 'ticket_quantity_4', 'ticket_description_4', 'ticket_attendees_per_ticket_4'
    ])
    
    # Write sample data with a comprehensive example
    writer.writerow([
        'Sample Conference 2025', 'This is a detailed description of the sample conference. You can include a very long description here with all the details about your event. There is no character limit for this field, so feel free to be as descriptive as needed.', 'Conference', 'Short conference description',
        '2025-12-01', '10:00', '2025-12-03', '17:00',
        'Sample Convention Center', '123 Sample St, Sample City, SC 12345', 'https://maps.google.com/?q=sample', '500',
        '2025-11-15 23:59', 'No outside food or drinks allowed.', 'All ticket sales are final.', 'Ages 18+',
        'PUBLISHED', 'True',
        'General Admission', '50.00', '200', 'Standard entry to all sessions', '1',
        'VIP Pass', '150.00', '50', 'Priority seating and exclusive networking event', '1',
        'Group Pass', '200.00', '30', 'Entry for up to 5 team members', '5',
        'Student Pass', '25.00', '100', 'Discounted rate for students with valid ID', '1'
    ])
    
    # Add a second example that shows minimum required fields
    writer.writerow([
        'Minimum Required Example', 'Basic event description', 'Workshop', '',
        '2025-09-15', '09:00', '', '',
        'TBD', '', '', '50',
        '', '', '', '',
        'DRAFT', 'False',
        'Standard Ticket', '10.00', '50', '', '1',
        '', '', '', '', '',
        '', '', '', '', '',
        '', '', '', '', ''
    ])
    
    return output.getvalue()

def generate_tickets_for_purchase(user, ticket_type, quantity=1):
    """
    Generate tickets for a user and ticket type.
    Returns a list of created Ticket objects.
    """
    tickets = []
    event = ticket_type.event
    for _ in range(quantity):
        ticket_number = str(uuid.uuid4())[:8].upper()
        ticket = Ticket.objects.create(
            event=event,
            ticket_type=ticket_type,
            customer=user,
            ticket_number=ticket_number,
            status='VALID',
            purchase_date=timezone.now(),
            unique_secure_token=str(uuid.uuid4())
        )
        tickets.append(ticket)
    return tickets
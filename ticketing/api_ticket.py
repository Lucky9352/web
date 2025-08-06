from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.contrib.auth.decorators import login_required
import json
import uuid
import qrcode
import random
import string
import hmac
import hashlib
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
from django.conf import settings
import base64
import hmac
import hashlib
import os
import logging
from django.conf import settings

from .models import User, TicketType, Ticket

# Get the logger instance for this module
logger = logging.getLogger(__name__)

@require_http_methods(["POST"])
def api_checkout_ticket(request):
    """API endpoint for ticket checkout"""
    try:
        # Parse JSON data
        data = json.loads(request.body)
        user_id = data.get('user_id')
        ticket_type_id = data.get('ticket_type_id')
        
        # Validate data
        if not user_id or not ticket_type_id:
            return JsonResponse({
                'success': False,
                'message': 'Missing required data: user_id or ticket_type_id'
            }, status=400)
            
        # Get user and ticket type
        user = get_object_or_404(User, id=user_id)
        ticket_type = get_object_or_404(TicketType, id=ticket_type_id)
        event = ticket_type.event
        
        # Check event capacity
        if event.remaining_attendee_capacity < ticket_type.attendees_per_ticket:
            return JsonResponse({
                'success': False,
                'message': 'Insufficient event capacity'
            }, status=400)
        
        # Generate unique ticket number and secure token
        ticket_number = generate_ticket_number()
        unique_secure_token = str(uuid.uuid4())
        
        # Create ticket
        ticket = Ticket.objects.create(
            event=event,
            ticket_type=ticket_type,
            customer=user,
            ticket_number=ticket_number,
            status='VALID',  # Set status to VALID as required
            purchase_date=timezone.now(),
            unique_secure_token=unique_secure_token
        )
        
        return JsonResponse({
            'success': True,
            'ticket_id': ticket.id,
            'message': 'Ticket created successfully'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error creating ticket: {str(e)}'
        }, status=500)

def generate_ticket_number():
    """Generate a unique ticket number"""
    import random
    import string
    
    prefix = ''.join(random.choices(string.ascii_uppercase, k=2))
    number = ''.join(random.choices(string.digits, k=6))
    return f"{prefix}{number}"

@login_required
@require_http_methods(["GET"])
def api_download_ticket(request, ticket_id):
    """API endpoint for on-demand ticket generation"""
    try:
        # Get ticket and verify ownership
        ticket = get_object_or_404(Ticket, id=ticket_id)
        
        # Security check - make sure the user owns this ticket or is admin
        if request.user != ticket.customer and request.user.role != 'ADMIN':
            return JsonResponse({
                'success': False,
                'message': 'Unauthorized access'
            }, status=403)
        
        # Get ticket type
        ticket_type = ticket.ticket_type
        
        # Generate ticket image
        ticket_image = generate_ticket_image(ticket)
        
        # Convert image to base64 string for response
        buffered = BytesIO()
        ticket_image.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return JsonResponse({
            'success': True,
            'ticket_image': img_str,
            'ticket_number': ticket.ticket_number,
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error generating ticket: {str(e)}'
        }, status=500)

def generate_ticket_image(ticket):
    """Generate a ticket image with QR code"""
    try:
        # Get ticket details
        event = ticket.event
        ticket_type = ticket.ticket_type
        
        # Check if template exists and try to load it
        template_path = None
        if hasattr(ticket_type, 'image_template_url') and ticket_type.image_template_url:
            template_path = os.path.join(settings.MEDIA_ROOT, str(ticket_type.image_template_url))
        
        # Create template image - either from file or blank canvas
        if template_path and os.path.exists(template_path):
            try:
                template = Image.open(template_path).convert('RGBA')
                # Resize if needed to ensure consistent dimensions
                template = template.resize((800, 400))
            except Exception as e:
                # If there's any error loading the template, fall back to blank
                logger.error(f"Error loading template: {e}")
                template = Image.new('RGBA', (800, 400), color=(255, 255, 255, 255))
        else:
            # Create a blank template if no template file exists
            template = Image.new('RGBA', (800, 400), color=(255, 255, 255, 255))
    except Exception as e:
        pass
    # Generate QR code with signed data
    qr_data = create_signed_ticket_data(ticket)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_data)
    qr.make(fit=True)
    
    qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGBA')
    
    # Set the QR code size to 200x200 pixels as specified
    qr_size = 200
    qr_img = qr_img.resize((qr_size, qr_size))
    
    # Position QR code at the specified coordinates (670, 20) in the blank black rectangle area
    position = (670, 20)
    
    # Create a copy of the template before pasting to avoid modifying the original
    result_image = template.copy()
    
    # Create a composite image
    result_image.paste(qr_img, position, qr_img)
    
    # Add text information using PIL's ImageDraw
    draw = ImageDraw.Draw(result_image)
    
    try:
        # Try to use a system font
        font = ImageFont.truetype("arial.ttf", 16)
    except IOError:
        font = ImageFont.load_default()
    
    # Add ticket information text
    text_y = 30
    draw.text((20, text_y), f"Event: {event.title}", fill=(0, 0, 0), font=font)
    text_y += 25
    draw.text((20, text_y), f"Date: {event.date.strftime('%B %d, %Y')}", fill=(0, 0, 0), font=font)
    text_y += 25
    draw.text((20, text_y), f"Time: {event.time.strftime('%I:%M %p')}", fill=(0, 0, 0), font=font)
    text_y += 25
    draw.text((20, text_y), f"Venue: {event.venue}", fill=(0, 0, 0), font=font)
    text_y += 25
    draw.text((20, text_y), f"Ticket Type: {ticket_type.type_name}", fill=(0, 0, 0), font=font)
    text_y += 25
    draw.text((20, text_y), f"Ticket #: {ticket.ticket_number}", fill=(0, 0, 0), font=font)
    text_y += 25
    draw.text((20, text_y), f"Attendees: {ticket_type.attendees_per_ticket}", fill=(0, 0, 0), font=font)
    
    return result_image

def create_signed_ticket_data(ticket):
    """Create signed ticket data for QR code"""
    try:
        # Ensure the ticket has a unique secure token
        if not hasattr(ticket, 'unique_secure_token') or not ticket.unique_secure_token:
            unique_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            ticket.unique_secure_token = unique_id
            ticket.save()
        
        timestamp = int(timezone.now().timestamp())
        
        # Create ticket data in the compact format that the scanner expects
        ticket_data = {
            'tid': ticket.id,  # Compact name for ticket_id
            'tok': ticket.unique_secure_token,  # Compact name for token
            'ts': timestamp,   # Timestamp
        }
        
        # Create signature
        secret_key = settings.SECRET_KEY.encode()
        message = f"{ticket.id}:{ticket.unique_secure_token}:{timestamp}".encode()
        signature = hmac.new(secret_key, message, hashlib.sha256).hexdigest()[:16]
        ticket_data['sig'] = signature
        
        return json.dumps(ticket_data)
    except Exception as e:
        logger.error(f"Error in create_signed_ticket_data: {str(e)}")
        # Return a simple fallback value that will still work for validation
        return json.dumps({'tid': ticket.id, 'tok': ticket.unique_secure_token})

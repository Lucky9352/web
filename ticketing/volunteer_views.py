import json
import logging
import hmac
import hashlib
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
from django.conf import settings
from django.db import transaction
from .models import Ticket

# Get the logger instance for this module
logger = logging.getLogger(__name__)

def is_volunteer(user):
    """Helper function to check if a user is a volunteer"""
    return user.is_authenticated and user.role == 'VOLUNTEER'

@login_required
@user_passes_test(is_volunteer)
def volunteer_dashboard(request):
    """Main volunteer dashboard view"""
    # You could add event assignment information here
    return render(request, 'core/volunteer/dashboard.html')

@login_required
@user_passes_test(is_volunteer)
def volunteer_scan_tickets(request):
    """View for volunteer ticket scanning interface"""
    return render(request, 'core/volunteer/scan_tickets.html')

@login_required
@user_passes_test(lambda u: u.role in ['VOLUNTEER', 'ADMIN', 'ORGANIZER'])
@require_http_methods(["POST"])
@csrf_exempt  # For simplicity in the example; consider using proper CSRF protection in production
def api_validate_ticket(request):
    """API endpoint for validating tickets via QR code scan"""
    try:
        # Parse the request data
        data = json.loads(request.body)
        
        # Support both new compact format and legacy format
        ticket_id = data.get('tid') or data.get('ticket_id')
        unique_secure_token = data.get('tok') or data.get('unique_secure_token')
        timestamp = data.get('ts')  # Timestamp for validation (optional)
        signature = data.get('sig')  # HMAC signature (optional)
        
        # Validate required fields
        if not ticket_id or not unique_secure_token:
            return JsonResponse({
                'success': False,
                'message': 'Missing required data'
            }, status=400)
        
        # Find the ticket by ID
        try:
            ticket = get_object_or_404(Ticket, id=ticket_id)
        except:
            return JsonResponse({
                'success': False,
                'message': 'Ticket not found'
            }, status=404)
        
        # Verify the secure token
        if ticket.unique_secure_token != unique_secure_token:
            # Log security incident
            logger.warning(f"Invalid token attempt for ticket ID: {ticket_id}")
            return JsonResponse({
                'success': False,
                'message': 'Invalid ticket token'
            }, status=403)
            
        # Verify signature if provided
        if signature and timestamp:
            try:
                secret_key = settings.SECRET_KEY.encode()
                message = f"{ticket_id}:{unique_secure_token}:{timestamp}".encode()
                expected_signature = hmac.new(secret_key, message, hashlib.sha256).hexdigest()[:16]
                
                if signature != expected_signature:
                    logger.warning(f"Invalid signature for ticket ID: {ticket_id}")
                    return JsonResponse({
                        'success': False,
                        'message': 'Invalid ticket signature'
                    }, status=403)
            except Exception as e:
                logger.error(f"Error verifying signature: {str(e)}")
                # Continue without signature verification if an error occurs
        
        # Check ticket status
        if ticket.status == 'USED':
            # Enhanced response for already used tickets
            used_at_str = None
            validated_by_name = None
            
            if hasattr(ticket, 'used_at') and ticket.used_at:
                used_at_str = ticket.used_at.strftime('%B %d, %Y at %I:%M %p')
            
            if hasattr(ticket, 'validated_by') and ticket.validated_by:
                validated_by_name = f"{ticket.validated_by.first_name} {ticket.validated_by.last_name}"
            
            return JsonResponse({
                'success': False,
                'error_code': 'ALREADY_USED',
                'message': 'This ticket has already been used',
                'ticket_number': ticket.ticket_number,
                'ticket_type_name': ticket.ticket_type.type_name if ticket.ticket_type else 'Unknown Type',
                'event_name': ticket.event.title if ticket.event else 'Unknown Event',
                'used_at': used_at_str,
                'validated_by': validated_by_name
            })
        
        elif ticket.status != 'VALID':
            return JsonResponse({
                'success': False,
                'error_code': 'INVALID_STATUS',
                'message': f'Invalid ticket status: {ticket.get_status_display()}',
                'ticket_number': ticket.ticket_number,
                'ticket_type_name': ticket.ticket_type.type_name if ticket.ticket_type else 'Unknown Type',
                'event_name': ticket.event.title if ticket.event else 'Unknown Event'
            })
        
        # Ticket is valid, update status with transaction
        with transaction.atomic():
            ticket.status = 'USED'
            ticket.used_at = timezone.now()
            ticket.validated_by = request.user
            ticket.save()
            
            # Log the validation
            logger.info(f"Ticket {ticket.ticket_number} validated by {request.user.email} at {ticket.used_at}")
        
        # Return success response with ticket details
        return JsonResponse({
            'success': True,
            'message': 'Ticket validated successfully',
            'ticket_number': ticket.ticket_number,
            'ticket_type_name': ticket.ticket_type.type_name if ticket.ticket_type else 'General Admission',
            'entry_count': ticket.ticket_type.attendees_per_ticket if ticket.ticket_type else 1,
            'event_name': ticket.event.title,
        })
        
    except Exception as e:
        logger.error(f"Error validating ticket: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'Error processing ticket: {str(e)}'
        }, status=500)

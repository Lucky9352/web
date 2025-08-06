import json
import hmac
import hashlib
import logging
import traceback
from django.db import transaction
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.conf import settings
from ticketing.models import Ticket
from ticketing.views import is_volunteer

# Get the logger instance for this module
logger = logging.getLogger(__name__)

@login_required
@user_passes_test(is_volunteer)
def volunteer_scan_tickets(request):
    """View for volunteer ticket scanning interface"""
    return render(request, 'core/volunteer/scan_tickets.html')

@login_required
@user_passes_test(lambda u: u.role in ['VOLUNTEER', 'ADMIN', 'ORGANIZER'])
@require_http_methods(["POST"])
def api_validate_ticket(request):
    """API endpoint for validating tickets via QR code scan"""
    try:
        # Parse the request data
        data = json.loads(request.body)
        
        # Support both formats - new compact format and legacy format
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
        except Exception as e:
            logger.error(f"Error finding ticket {ticket_id}: {str(e)}")
            return JsonResponse({
                'success': False,
                'message': 'Ticket not found'
            }, status=404)
        
        # Verify the secure token
        if ticket.unique_secure_token != unique_secure_token:
            # Log security incident
            logger.warning(f"Invalid token attempt for ticket ID: {ticket_id} - Provided: {unique_secure_token}, Expected: {ticket.unique_secure_token}")
            return JsonResponse({
                'success': False,
                'message': 'Invalid ticket token'
            }, status=403)
        
        # Verify signature if provided
        if signature and timestamp:
            secret_key = settings.SECRET_KEY.encode()
            message = f"{ticket_id}:{unique_secure_token}:{timestamp}".encode()
            expected_signature = hmac.new(secret_key, message, hashlib.sha256).hexdigest()[:16]
            
            if signature != expected_signature:
                logger.warning(f"Invalid signature for ticket ID: {ticket_id}")
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid ticket signature'
                }, status=403)
        
        # Check ticket status
        if ticket.status == 'USED':
            # Provide details on when and by whom the ticket was already used
            return JsonResponse({
                'success': False,
                'message': 'This ticket has already been used',
                'ticket_number': ticket.ticket_number,
                'used_at': ticket.used_at.strftime('%Y-%m-%d %H:%M:%S') if ticket.used_at else None,
                'validated_by': ticket.validated_by.email if ticket.validated_by else 'Unknown'
            })
        
        elif ticket.status != 'VALID':
            return JsonResponse({
                'success': False,
                'message': f'Invalid ticket status: {ticket.get_status_display()}',
                'ticket_number': ticket.ticket_number,
                'status': ticket.status
            })
        
        # Ticket is valid, update status with transaction
        with transaction.atomic():
            ticket.status = 'USED'
            ticket.used_at = timezone.now()
            ticket.validated_by = request.user
            ticket.save()
            
            # Log the validation
            logger.info(f"Ticket {ticket.ticket_number} validated by {request.user.email} at {ticket.used_at}")
        
        # Return success response with complete ticket details
        return JsonResponse({
            'success': True,
            'message': 'Ticket validated successfully',
            'ticket_number': ticket.ticket_number,
            'ticket_type_name': ticket.ticket_type.type_name if ticket.ticket_type else 'General Admission',
            'entry_count': ticket.ticket_type.attendees_per_ticket if ticket.ticket_type else 1,
            'event_name': ticket.event.title,
            'event_date': ticket.event.date.strftime('%B %d, %Y'),
            'validation_time': timezone.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'message': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        logger.error(f"Error validating ticket: {str(e)}")
        logger.error(traceback.format_exc())  # Log full traceback for debugging
        return JsonResponse({
            'success': False,
            'message': f'Error processing ticket: {str(e)}'
        }, status=500)

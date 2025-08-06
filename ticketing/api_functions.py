from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from .models import Event, TicketType, User, Ticket, PromoCode, EventStaff, PromoCodeUsage
from .forms import (
    EventForm, CustomUserCreationForm, TicketForm, PromoCodeForm,
    EventStaffForm, TicketTypeForm
)
from .utils import handle_event_csv_upload, generate_sample_csv

def is_admin(user):
    return user.is_authenticated and user.role == 'ADMIN'

# Add this at the end of the file
@login_required
@user_passes_test(is_admin)
@require_http_methods(["GET"])
def api_get_event_ticket_types(request, event_id):
    """API endpoint to get all ticket types for an event"""
    try:
        event = get_object_or_404(Event, id=event_id)
        ticket_types = event.ticket_types.all()
        
        result = []
        for ticket_type in ticket_types:
            result.append({
                'id': ticket_type.id,
                'type_name': ticket_type.type_name,
                'price': float(ticket_type.price),
                'quantity': ticket_type.quantity,
                'description': ticket_type.description,
                'attendees_per_ticket': ticket_type.attendees_per_ticket
            })
            
        return JsonResponse({
            'success': True,
            'ticket_types': result
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error fetching ticket types: {str(e)}'
        }, status=400)

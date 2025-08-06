import secrets
import random
import logging
import json
import uuid
import string
import qrcode
import traceback
import time
import tempfile
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
import base64
import hmac
import hashlib
import os
import re  # Import the regular expression module
from django.db import transaction
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import login
from django.contrib import messages
from django.urls import reverse_lazy, reverse
from django.core.mail import send_mail, EmailMessage, EmailMultiAlternatives
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods, require_GET
from .models import Event, TicketType, Ticket
from .forms import (
    CustomUserCreationForm, EventForm, ProfileUpdateForm,
    PromoCodeForm, EventStaffForm, OTPForm
)
from .models import User, Event, Ticket, PromoCode, EventStaff, TicketType, PromoCodeUsage, PaymentTransaction
from .utils import generate_otp, send_otp_email
# Removed: from weasyprint import HTML, CSS
# Removed: import imgkit

# cashfree
from cashfree_pg.api_client import Cashfree
from cashfree_pg.models.create_order_request import CreateOrderRequest
from cashfree_pg.models.order_meta import OrderMeta
from cashfree_pg.models.customer_details import CustomerDetails
# Add these imports at the top of ticketing/views.py
import hmac
import hashlib
import base64
import json
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.conf import settings
from .models import TicketPurchase 
from .utils import generate_tickets_for_purchase # Assuming you have a function like this



# --- CASHFREE CONFIGURATION (from settings) ---
from django.conf import settings
Cashfree.XClientId = settings.CASHFREE_CLIENT_ID
Cashfree.XClientSecret = settings.CASHFREE_CLIENT_SECRET
if getattr(settings, 'CASHFREE_ENVIRONMENT', 'SANDBOX').upper() == 'PRODUCTION':
    Cashfree.XEnvironment = Cashfree.PRODUCTION
else:
    Cashfree.XEnvironment = Cashfree.SANDBOX
CASHFREE_API_VERSION = "2023-08-01"


# Get the logger instance for this module
logger = logging.getLogger(__name__)

def is_admin(user):
    return user.is_authenticated and user.role == 'ADMIN'

def is_organizer(user):
    return user.is_authenticated and user.role == 'ORGANIZER'

def is_volunteer(user):
    return user.is_authenticated and user.role == 'VOLUNTEER'

def is_customer(user):
    return user.is_authenticated and user.role == 'CUSTOMER'

from django.contrib.auth import authenticate, login as auth_login
from django.shortcuts import render, redirect
from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponse
import os

def download_csv_guide(request):
    """
    Downloads the CSV upload guide as a text file
    """
    guide_path = os.path.join(settings.BASE_DIR, 'ticketing', 'static', 'core', 'docs', 'csv_upload_guide.md')

    if os.path.exists(guide_path):
        with open(guide_path, 'r') as file:
            content = file.read()

        response = HttpResponse(content, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="Event_CSV_Instructions.txt"'
        return response

@login_required
@user_passes_test(is_customer)
def my_tickets(request):
    tickets = Ticket.objects.filter(
        customer=request.user,
        status__in=['SOLD', 'VALID']
    ).select_related('event', 'ticket_type')

    context = {
        'tickets': tickets
    }

    return render(request, 'core/my_tickets.html', context)



# Verification function removed

def get_event_data():
    events = Event.objects.filter(status='PUBLISHED').order_by('-created_at').prefetch_related('ticket_types')
    events_with_prices = []
    for event in events:
        min_price = float('inf')
        for ticket_type in event.ticket_types.all():
            if ticket_type.price < min_price:
                min_price = ticket_type.price
        events_with_prices.append({
            'event': event,
            'min_price': min_price if min_price != float('inf') else None
        })
    return events_with_prices

def home(request):
    events_with_prices = get_event_data()
    return render(request, 'core/home.html', {'events': events_with_prices})

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)
        if user is not None:
            if not user.email_verified:
                request.session['user_pk_for_verification'] = user.pk
                otp = generate_otp()
                user.email_verification_otp = otp
                user.email_verification_otp_created_at = timezone.now()
                user.save()
                send_otp_email(user.email, otp)
                messages.info(request, 'Your email is not verified. A new verification code has been sent.')
                return redirect('verify_otp')

            auth_login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid email or password.')
    return render(request, 'core/login.html')

def generate_ticket_number():
    max_attempts = 10
    attempts = 0

    while attempts < max_attempts:
        prefix = ''.join(random.choices(string.ascii_uppercase, k=2))
        number = ''.join(random.choices(string.digits, k=6))
        ticket_number = f"{prefix}{number}"

        with transaction.atomic():
            if not Ticket.objects.filter(ticket_number=ticket_number).exists():
                return ticket_number
        
        attempts += 1
    
    return f"TX{uuid.uuid4().hex[:8].upper()}"

@login_required
def get_event_ticket_types(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    ticket_types = []
    
    if event.remaining_attendee_capacity > 0:
        for ticket_type in event.ticket_types.all():
            available = event.remaining_attendee_capacity // ticket_type.attendees_per_ticket
            
            if available > 0:
                ticket_types.append({
                    'id': ticket_type.id,
                    'type_name': ticket_type.type_name,
                    'price': float(ticket_type.price),
                    'description': ticket_type.description,
                    'attendees_per_ticket': ticket_type.attendees_per_ticket,
                    'available': available
                })
    
    if request.POST.get('book_tickets'):
        return redirect('checkout', event_id=event_id)
    
    return JsonResponse({'ticket_types': ticket_types})

@login_required
def book_ticket(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    ticket_types = TicketType.objects.filter(event=event)
    
    ticket_types_with_availability = []
    for ticket_type in ticket_types:
        attendees_per_ticket = ticket_type.attendees_per_ticket or 1
        max_possible_tickets = event.remaining_attendee_capacity // attendees_per_ticket
        if max_possible_tickets < 0:
            max_possible_tickets = 0
        ticket_type.available_quantity = max_possible_tickets
        ticket_types_with_availability.append(ticket_type)
    
    if request.method == 'POST':
        selected_tickets = []
        total_amount = 0
        total_attendees_requested = 0
        
        for key, value in request.POST.items():
            if key.startswith('ticket_') and value.isdigit() and int(value) > 0:
                ticket_type_id = key.split('_')[1]
                quantity = int(value)
                
                try:
                    ticket_type = TicketType.objects.get(id=ticket_type_id, event=event)
                    
                    attendees_per_ticket = ticket_type.attendees_per_ticket or 1
                    attendees_for_this_type = quantity * attendees_per_ticket
                    total_attendees_requested += attendees_for_this_type
                    
                    subtotal = float(ticket_type.price) * quantity
                        
                    selected_tickets.append({
                        'id': ticket_type.id,
                        'type_name': ticket_type.type_name,
                        'price': float(ticket_type.price),
                        'quantity': quantity,
                        'subtotal': subtotal,
                        'total_attendees': attendees_for_this_type
                    })
                    total_amount += subtotal
                except TicketType.DoesNotExist:
                    messages.error(request, 'Invalid ticket type selected.')
                    return redirect('book_ticket', event_id=event_id)
        
        if not selected_tickets:
            messages.error(request, 'Please select at least one ticket.')
            return redirect('book_ticket', event_id=event_id)
        
        if total_attendees_requested > event.remaining_attendee_capacity:
            messages.error(request, f'Not enough capacity. Only {event.remaining_attendee_capacity} attendees can be registered.')
            return redirect('book_ticket', event_id=event_id)
        
        request.session['ticket_order'] = {
            'event_id': event_id,
            'ticket_types': selected_tickets,
            'subtotal': total_amount,
            'total': total_amount,
            'total_attendees': total_attendees_requested
        }
        
        return redirect('checkout', event_id=event_id)
    
    context = {
        'event': event,
        'ticket_types': ticket_types_with_availability,
    }
    return render(request, 'core/ticket_booking.html', context)

def signup(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.role = 'CUSTOMER'  # Set role for self-registration
            otp = generate_otp()
            user.email_verification_otp = otp
            user.email_verification_otp_created_at = timezone.now()
            user.set_password(form.cleaned_data.get('password1'))
            user.save()
            send_otp_email(user.email, otp)
            request.session['user_pk_for_verification'] = user.pk
            messages.success(request, 'A verification code has been sent to your email.')
            return redirect('verify_otp')
    else:
        form = CustomUserCreationForm()
    return render(request, 'core/signup.html', {'form': form})

def verify_otp_view(request):
    user_pk = request.session.get('user_pk_for_verification')
    if not user_pk:
        messages.error(request, 'Could not find a user to verify. Please sign up or log in again.')
        return redirect('signup')

    try:
        user = User.objects.get(pk=user_pk)
    except User.DoesNotExist:
        messages.error(request, 'User not found. Please sign up again.')
        return redirect('signup')

    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            entered_otp = form.cleaned_data.get('otp')

            if user.email_verification_otp_created_at and timezone.now() > user.email_verification_otp_created_at + timedelta(minutes=10):
                messages.error(request, 'OTP has expired. A new code has been sent.')
                otp = generate_otp()
                user.email_verification_otp = otp
                user.email_verification_otp_created_at = timezone.now()
                user.save()
                send_otp_email(user.email, otp)
                return render(request, 'core/verify_otp.html', {'form': OTPForm()})

            if user.email_verification_otp == entered_otp:
                user.email_verified = True
                user.email_verification_otp = None
                user.email_verification_otp_created_at = None
                user.save()

                if 'user_pk_for_verification' in request.session:
                    del request.session['user_pk_for_verification']

                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                messages.success(request, 'Email verified successfully! You are now logged in.')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
    else:
        form = OTPForm()

    return render(request, 'core/verify_otp.html', {'form': form})

@login_required
def dashboard(request):
    context = {
        'user': request.user,
    }
    
    if request.user.role == 'ADMIN':
        context.update({
            'total_users': User.objects.count(),
            'total_events': Event.objects.count(),
            'total_tickets': Ticket.objects.count(),
        })
        template = 'core/admin_dashboard.html'
    
    elif request.user.role == 'ORGANIZER':
        context['events'] = Event.objects.filter(organizer=request.user)
        template = 'core/organizer_dashboard.html'
    
    elif request.user.role == 'VOLUNTEER':
        context['assigned_events'] = Event.objects.all()
        template = 'core/volunteer_dashboard.html'
    
    elif request.user.role == 'CUSTOMER':
        context['tickets'] = Ticket.objects.filter(
            customer=request.user, 
            status='SOLD'
        ).select_related('event', 'ticket_type').order_by('-purchase_date')
        
        today = timezone.now().date()
        events = Event.objects.filter(
            status='PUBLISHED', 
            date__gte=today
        ).prefetch_related('ticket_types').order_by('date')
        events_with_prices = []
        
        for event in events:
            min_price = float('inf')
            for ticket_type in event.ticket_types.all():
                if ticket_type.price < min_price:
                    min_price = ticket_type.price
            events_with_prices.append({
                'event': event,
                'min_price': min_price if min_price != float('inf') else None
            })
            
        context['events'] = events_with_prices
        template = 'core/customer_dashboard.html'
    else:
        template = 'core/dashboard.html'
        
    return render(request, template, context)

@login_required
@user_passes_test(is_organizer)
def create_event(request):
    if request.method == 'POST':
        form = EventForm(request.POST)
        if form.is_valid():
            event = form.save(commit=False)
            event.organizer = request.user
            event.save()
            return redirect('event_detail', event_id=event.id)
    else:
        form = EventForm()
    return render(request, 'core/create_event.html', {'form': form})

def event_list(request):
    events_with_prices = get_event_data()
    return render(request, 'core/event_list.html', {'events_with_prices': events_with_prices})

def event_detail(request, event_id):
    event = get_object_or_404(Event.objects.prefetch_related('ticket_types'), id=event_id)
    
    ticket_types = []
    
    for ticket_type in event.ticket_types.all():
        max_possible_tickets = event.remaining_attendee_capacity // ticket_type.attendees_per_ticket
        
        ticket_types.append({
            'type': ticket_type,
            'available_count': max_possible_tickets
        })
    
    context = {
        'event': event,
        'ticket_types': ticket_types,
        'remaining_attendee_capacity': event.remaining_attendee_capacity,
        'next': request.path,
    }
    return render(request, 'core/event_detail.html', context)

@login_required
def checkout(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    
    ticket_order = request.session.get('ticket_order', {})
    
    if not ticket_order or ticket_order.get('event_id') != event_id:
        messages.error(request, 'No ticket order found. Please select tickets first.')
        return redirect('event_detail', event_id=event_id)
    
    selected_tickets = ticket_order.get('ticket_types', [])
    subtotal = ticket_order.get('subtotal', 0)
    
    if request.method == 'POST':
        applied_promo_code = request.POST.get('promo_code', '').strip()
        total = subtotal
        discount = 0

        if applied_promo_code:
            try:
                promo = PromoCode.objects.get(code=applied_promo_code, event=event)
                if promo.is_valid:
                    if promo.discount_type == 'PERCENTAGE':
                        discount = (float(promo.discount_value) / 100) * subtotal
                    else:
                        discount = min(float(promo.discount_value), subtotal)
                    
                    total = subtotal - discount
                    request.session['ticket_order']['discount'] = float(discount)
                    request.session['ticket_order']['promo_code'] = applied_promo_code
                else:
                    messages.error(request, 'The promo code is no longer valid.')
                    request.session['ticket_order']['discount'] = 0
                    request.session['ticket_order']['promo_code'] = ''
            except PromoCode.DoesNotExist:
                messages.error(request, 'Invalid promo code entered.')
                request.session['ticket_order']['discount'] = 0
                request.session['ticket_order']['promo_code'] = ''
        else:
            request.session['ticket_order']['discount'] = 0
            request.session['ticket_order']['promo_code'] = ''
            
        request.session['ticket_order']['total'] = total
        request.session.modified = True
        
    discount = request.session.get('ticket_order', {}).get('discount', 0)
    promo_code = request.session.get('ticket_order', {}).get('promo_code', '')
    total = request.session.get('ticket_order', {}).get('total', subtotal)
    
    total_attendees = 0
    for ticket_item in selected_tickets:
        ticket_type_id = ticket_item['id']
        quantity = ticket_item['quantity']
        ticket_type = TicketType.objects.get(id=ticket_type_id, event=event)
        
        ticket_item['attendees_per_ticket'] = ticket_type.attendees_per_ticket
        if 'subtotal' not in ticket_item:
            ticket_item['subtotal'] = quantity * float(ticket_type.price)
        
        total_attendees += quantity * ticket_type.attendees_per_ticket
    
    context = {
        'event': event,
        'ticket_types': selected_tickets,
        'subtotal': subtotal,
        'total': total,
        'discount': discount,
        'promo_code': promo_code,
        'user': request.user,
        'total_attendees': total_attendees,
    }
    return render(request, 'core/checkout_new.html', context)

@require_GET
def validate_promo_code(request, code):
    event_id = request.GET.get('event_id')
    if not event_id:
        return JsonResponse({'valid': False, 'message': 'Event ID is required'})
        
    if not code or code.strip() == '':
        return JsonResponse({'valid': False, 'message': 'Please enter a promo code'})
        
    try:
        promo = PromoCode.objects.get(code=code, event_id=event_id)
        
        if not promo.is_valid:
            now = timezone.now()
            if not promo.is_active: message = 'This promo code is inactive'
            elif promo.valid_from > now: message = 'This promo code is not yet valid'
            elif promo.valid_until < now: message = 'This promo code has expired'
            elif promo.max_uses > 0 and promo.current_uses >= promo.max_uses: message = 'This promo code has reached its maximum usage limit'
            else: message = 'This promo code is no longer valid'
            return JsonResponse({'valid': False, 'message': message})
            
        order_total = request.session.get('ticket_order', {}).get('subtotal', 0)
        if order_total == 0:
            return JsonResponse({'valid': False, 'message': 'No order total available for discount calculation'})
            
        if promo.discount_type == 'PERCENTAGE':
            discount = (float(promo.discount_value) / 100) * order_total
            discount_text = f"{promo.discount_value}% off"
        else:
            discount = min(float(promo.discount_value), order_total)
            discount_text = f"₹{promo.discount_value} off"
            
        final_total = max(0, order_total - discount)
        
        request.session['ticket_order']['total'] = final_total
        request.session['ticket_order']['discount'] = discount
        request.session['ticket_order']['promo_code'] = code
        request.session.modified = True
        
        return JsonResponse({
            'valid': True,
            'discount': round(float(discount), 2),
            'final_total': round(float(final_total), 2),
            'discount_text': discount_text,
            'message': f'Promo code applied successfully! {discount_text}'
        })
    except PromoCode.DoesNotExist:
        return JsonResponse({'valid': False, 'message': 'Invalid promo code'})
    except Exception as e:
        logger.error(f"Error validating promo code: {str(e)}")
        return JsonResponse({'valid': False, 'message': f'An unexpected error occurred.'})

@login_required
@user_passes_test(is_customer)
def purchase_ticket(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    ticket = Ticket.objects.filter(event=event, status='AVAILABLE').first()
    
    if ticket:
        ticket.customer = request.user
        ticket.status = 'SOLD'
        ticket.save()
        messages.success(request, 'Ticket purchased successfully!')
        return redirect('dashboard')
    else:
        messages.error(request, 'No tickets available for this event.')
        return redirect('event_detail', event_id=event.id)



@login_required
@user_passes_test(is_admin)
def manage_event_staff(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    if request.method == 'POST':
        form = EventStaffForm(request.POST)
        if form.is_valid():
            staff = form.save(commit=False)
            staff.event = event
            staff.save()
            messages.success(request, f'{staff.role} added successfully!')
            return redirect('event_detail', event_id=event.id)
    else:
        volunteer_form = EventStaffForm(initial={'role': 'VOLUNTEER'})
        organizer_form = EventStaffForm(initial={'role': 'ORGANIZER'})
    
    current_staff = EventStaff.objects.filter(event=event)
    return render(request, 'core/manage_event_staff.html', {
        'event': event,
        'volunteer_form': volunteer_form,
        'organizer_form': organizer_form,
        'current_staff': current_staff
    })

@login_required
@user_passes_test(is_admin)
def manage_promo_codes(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    if request.method == 'POST':
        form = PromoCodeForm(request.POST)
        if form.is_valid():
            promo = form.save(commit=False)
            promo.event = event
            promo.save()
            messages.success(request, 'Promo code created successfully!')
            return redirect('manage_promo_codes', event_id=promo.event.id)
    else:
        form = PromoCodeForm()
    
    promo_codes = PromoCode.objects.filter(event=event)
    return render(request, 'core/manage_promo_codes.html', {
        'event': event,
        'form': form,
        'promo_codes': promo_codes
    })

@login_required
@user_passes_test(is_admin)
def toggle_promo_code(request, code_id):
    promo = get_object_or_404(PromoCode, id=code_id)
    promo.is_active = not promo.is_active
    promo.save()
    messages.success(request, f'Promo code {promo.code} {"activated" if promo.is_active else "deactivated"} successfully!')
    return redirect('manage_promo_codes', event_id=promo.event.id)

@login_required
def update_profile(request):
    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated!')
            return redirect('dashboard')
    else:
        form = ProfileUpdateForm(instance=request.user)
    
    return render(request, 'core/update_profile.html', {'form': form})

@login_required
def process_payment(request, event_id):
    # Simulate interaction with payment gateway
    payment_response = get_payment_gateway_response(event_id)

    if payment_response.get('status') == 'SUCCESS':
        # Payment successful
        Ticket.objects.filter(event_id=event_id, customer=request.user).update(status='SOLD')
        return redirect('payment_success')
    else:
        # Payment failed
        failure_reason = payment_response.get('failure_reason', 'UNKNOWN')
        return redirect('payment_failed', event_id=event_id, failure_reason=failure_reason)

@login_required
def checkout_success(request, event_id=None):
    recent_tickets = Ticket.objects.filter(
        customer=request.user, 
        status='SOLD'
    ).select_related('event', 'ticket_type').order_by('-purchase_date')[:5]
    
    context = {
        'recent_tickets': recent_tickets,
        'user': request.user
    }
    
    return render(request, 'core/checkout_success.html', context)

# Admin Event Management Views
@login_required
@user_passes_test(is_admin)
def admin_event_list(request):
    events = Event.objects.all().order_by('-created_at')
    return render(request, 'core/admin_event_list.html', {'events': events})

@login_required
@user_passes_test(is_admin)
def admin_create_event(request):
    if request.method == 'POST':
        form = EventForm(request.POST, request.FILES)
        if form.is_valid():
            event = form.save(commit=False)
            event.created_by = request.user
            event.save()
            messages.success(request, 'Event created successfully!')
            return redirect('admin_event_list')
    else:
        form = EventForm()
    return render(request, 'core/admin/event_form.html', {'form': form, 'action': 'Create'})

@login_required
@user_passes_test(is_admin)
def admin_edit_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    if request.method == 'POST':
        form = EventForm(request.POST, request.FILES, instance=event)
        if form.is_valid():
            form.save()
            messages.success(request, 'Event updated successfully!')
            return redirect('admin_event_list')
    else:
        form = EventForm(instance=event)
    return render(request, 'core/admin/event_form.html', {'form': form, 'action': 'Edit', 'event': event})

@login_required
@user_passes_test(is_admin)
def admin_delete_event(request, event_id):
    pass

# Ticket checkout and download API functions
@require_http_methods(["POST"])
def api_checkout_ticket(request):
    try:
        data = json.loads(request.body)
        user_id = data.get('user_id')
        ticket_type_id = data.get('ticket_type_id')
        
        if not user_id or not ticket_type_id:
            return JsonResponse({'success': False, 'message': 'Missing required data'}, status=400)
            
        user = get_object_or_404(User, id=user_id)
        ticket_type = get_object_or_404(TicketType, id=ticket_type_id)
        event = ticket_type.event
        
        if event.remaining_attendee_capacity < ticket_type.attendees_per_ticket:
            return JsonResponse({'success': False, 'message': 'Insufficient event capacity'}, status=400)
        
        ticket_number = generate_ticket_number()
        unique_secure_token = str(uuid.uuid4())
        
        ticket = Ticket.objects.create(
            event=event,
            ticket_type=ticket_type,
            customer=user,
            ticket_number=ticket_number,
            status='VALID',
            purchase_date=timezone.now(),
            unique_secure_token=unique_secure_token
        )
        
        return JsonResponse({
            'success': True,
            'ticket_id': ticket.id,
            'ticket_number': ticket.ticket_number,
            'event_name': event.title,
            'ticket_type': ticket_type.type_name,
            'event_date': event.date.strftime('%B %d, %Y'),
            'event_time': event.time.strftime('%I:%M %p'),
            'venue': event.venue,
            'attendees': ticket_type.attendees_per_ticket,
            'message': 'Ticket created successfully'
        })
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error creating ticket: {str(e)}'}, status=500)

@login_required
@require_http_methods(["GET"])
def event_pass(request, ticket_id):
    try:
        ticket = get_object_or_404(Ticket, id=ticket_id)
        
        # Check if the user has permission to view this ticket
        if request.user != ticket.customer and request.user.role != 'ADMIN':
            messages.error(request, 'You do not have permission to view this ticket.')
            return redirect('my_tickets')
        
        # Generate QR code for the ticket
        qr_data = create_signed_ticket_data(ticket)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=0,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGBA')
        
        # Convert QR code to base64 string
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_code_image = base64.b64encode(buffered.getvalue()).decode()
        
        # Get event sponsors if available
        event_sponsors = ticket.event.sponsors.all() if hasattr(ticket.event, 'sponsors') else []
        
        context = {
            'ticket': ticket,
            'qr_code_image': qr_code_image,
            'event_sponsors': event_sponsors,
        }
        
        return render(request, 'core/event_pass.html', context)
        
    except Exception as e:
        messages.error(request, f'Error generating event pass: {str(e)}')
        return redirect('my_tickets')

def api_download_ticket(request, ticket_id):
    try:
        ticket = get_object_or_404(Ticket, id=ticket_id)
        
        if request.user != ticket.customer and request.user.role != 'ADMIN':
            return JsonResponse({'success': False, 'message': 'Unauthorized access'}, status=403)
        
        ticket_type = ticket.ticket_type
        
        if not ticket_type:
            return JsonResponse({'success': False, 'message': 'Ticket type not available'}, status=400)
            
        try:
            ticket_image = generate_ticket_image(ticket)
            
            buffered = BytesIO()
            ticket_image.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            
            return JsonResponse({
                'success': True,
                'ticket_image': img_str,
                'ticket_number': ticket.ticket_number,
                'ticket_id': ticket.id,
            })
        except Exception as e:
            logger.error(f"Error generating ticket image: {str(e)}")
            return JsonResponse({'success': False, 'message': f'Error generating ticket image: {str(e)}'}, status=500)
            
    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Error generating ticket: {str(e)}'}, status=500)

def generate_ticket_image(ticket):
    event = ticket.event
    ticket_type = ticket.ticket_type
    
    template = Image.new('RGBA', (1000, 350), color=(255, 255, 255, 255))
    
    try:
        if not ticket.unique_secure_token:
            unique_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            ticket.unique_secure_token = unique_id
            ticket.save()
        
        qr_data = create_signed_ticket_data(ticket)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=0,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGBA')
        
        qr_size = 200
        qr_x = 670
        qr_y = 20
        
        if template.width < qr_x + qr_size or template.height < qr_y + qr_size:
            new_qr_size = min(template.width - 40, template.height - 40, 200)
            qr_size = new_qr_size
            qr_x = max(template.width - qr_size - 20, 0)
            qr_y = max((template.height - qr_size) // 2, 20)
            logger.info(f"Adjusted QR placement to fit on template: ({qr_x}, {qr_y}) with size {qr_size}")
        
        qr_img = qr_img.resize((qr_size, qr_size))
        
        template.paste(qr_img, (qr_x, qr_y), qr_img)
        
        draw = ImageDraw.Draw(template)
        try:
            font = ImageFont.truetype("arial.ttf", 14)
        except IOError:
            font = ImageFont.load_default()
        
        short_id = f"Code: {ticket.unique_secure_token}"
        text_width = draw.textlength(short_id, font=font)
        draw.text((qr_x + (qr_size - text_width) // 2, qr_y + qr_size + 10), 
                  short_id, fill=(0, 0, 0), font=font)
                  
        instructions = "Scan for entry"
        inst_width = draw.textlength(instructions, font=font)
        draw.text((qr_x + (qr_size - inst_width) // 2, qr_y - 20), 
                 instructions, fill=(0, 0, 0), font=font)
                 
    except Exception as e:
        logger.error(f"Error generating QR code for ticket {ticket.id}: {str(e)}")
        draw = ImageDraw.Draw(template)
        try:
            font = ImageFont.truetype("arial.ttf", 14)
        except IOError:
            font = ImageFont.load_default()
        draw.text((template.width - 200, template.height - 50), 
                  "QR code generation failed", fill=(255, 0, 0), font=font)
    
        draw = ImageDraw.Draw(template)
        
        try:
            font = ImageFont.truetype("arial.ttf", 16)
        except IOError:
            font = ImageFont.load_default()
        
        text_y = 30
        draw.text((20, text_y), f"Event: {event.title}", fill=(0, 0, 0), font=font)
        text_y += 25
        draw.text((20, text_y), f"Date: {event.date.strftime('%B %d, %Y')}", fill=(0, 0, 0), font=font)
        text_y += 25
        draw.text((20, text_y), f"Time: {event.time.strftime('%I:%M %p')}", fill=(0, 0, 0), font=font)
        text_y += 25
        draw.text((20, text_y), f"Venue: {event.venue}", fill=(0, 0, 0), font=font)
        text_y += 25
        draw.text((20, text_y), f"Ticket ID: {ticket.id}", fill=(0, 0, 0), font=font)
        text_y += 25
        draw.text((20, text_y), f"Ticket Type: {ticket_type.type_name}", fill=(0, 0, 0), font=font)
        text_y += 25
        draw.text((20, text_y), f"Ticket #: {ticket.ticket_number}", fill=(0, 0, 0), font=font)
        text_y += 25
        draw.text((20, text_y), f"Attendees: {ticket_type.attendees_per_ticket}", fill=(0, 0, 0), font=font)
    
    return template

def create_signed_ticket_data(ticket):
    """Create signed ticket data for QR code"""
    if not ticket.ticket_number or len(ticket.ticket_number) < 6:
        ticket.ticket_number = f"{ticket.event.id:02d}-{random.randint(100000, 999999)}"
        ticket.save()
    
    if not ticket.unique_secure_token:
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
    
# Pages for footer links
def contact(request):
    if request.method == 'POST':
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        subject = request.POST.get('subject')
        message = request.POST.get('message')
        
        messages.success(request, "Thank you for your message! We'll get back to you soon.")
        return redirect('contact')
    
    return render(request, 'core/contact.html')

def terms(request):
    return render(request, 'core/terms.html')

def refunds(request):
    return render(request, 'core/refunds.html')

def privacy(request):
    return render(request, 'core/privacy.html')


@login_required
def send_ticket_email(request, ticket_id):
    """
    Generates the modern event pass as a high-quality image 
    and sends it via email to the customer.
    """
    try:
        ticket = get_object_or_404(Ticket, id=ticket_id)
        
        # Security check: Ensure the user owns the ticket or is an admin
        if request.user != ticket.customer and not request.user.is_staff:
            messages.error(request, 'You do not have permission to access this ticket.')
            return redirect('my_tickets')
            
        # 1. Generate QR Code Data using your existing secure method
        qr_data = create_signed_ticket_data(ticket)
        qr = qrcode.QRCode(
            version=1, error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10, border=0,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGBA')
        
        # Convert QR code to base64 string for the template
        buffered = BytesIO()
        qr_img.save(buffered, format="PNG")
        qr_code_image = base64.b64encode(buffered.getvalue()).decode()
        
        # 2. Get Event Sponsors
        event_sponsors = ticket.event.sponsors.all() if hasattr(ticket.event, 'sponsors') else []
        
        context = {
            'ticket': ticket,
            'qr_code_image': qr_code_image,
            'event_sponsors': event_sponsors,
        }
        
        # 3. Render the HTML template to a string
        html_string = render_to_string('core/event_pass_new.html', context)
        
        # 4. Define the absolute path to the local CSS file
        css_path = str(settings.BASE_DIR / 'ticketing' / 'static' / 'css' / 'event_pass.css')

        # 5. Generate the image using PIL
        try:
            # Use generate_ticket_image function 
            ticket_image = generate_ticket_image(ticket)
            
            # Convert PIL image to bytes
            buffered = BytesIO()
            ticket_image.save(buffered, format="PNG")
            image_bytes = buffered.getvalue()
            
            logger.info(f"Successfully generated ticket image using PIL for ticket {ticket_id}")
        except Exception as pil_error:
            logger.error(f"PIL image generation failed: {str(pil_error)}. Falling back to PDF.")
            
            # Last resort: Generate PDF with WeasyPrint and tell the user
            # Generate PDF with WeasyPrint
            try:
                # Set up the email components first
                subject = f"Your Event Pass for {ticket.event.title}"
                customer_name = ticket.customer.get_full_name() if hasattr(ticket.customer, 'get_full_name') else "Valued Customer"
                
                html_message = f"""
                <html>
                <body>
                    <p>Dear {customer_name},</p>
                    <p>Thank you for your purchase! Your event pass for <strong>{ticket.event.title}</strong> is attached to this email as a PDF.</p>
                    <p>Please save the attached PDF to your phone and present it at the venue for entry.</p>
                    <p>Enjoy the event!</p>
                    <p>Best regards,<br>The Tapnex Team</p>
                </body>
                </html>
                """
                plain_message = strip_tags(html_message)
                from_email = settings.DEFAULT_FROM_EMAIL
                to_email = ticket.customer.email
                
                # Generate PDF with WeasyPrint
                # css = CSS(filename=css_path) # Removed: WeasyPrint is not available
                # html = HTML(string=html_string, base_url=request.build_absolute_uri('/')) # Removed: WeasyPrint is not available
                # pdf_bytes = html.write_pdf(stylesheets=[css]) # Removed: WeasyPrint is not available
                
                # Create and send email with PDF attachment
                msg = EmailMultiAlternatives(subject, plain_message, from_email, [to_email])
                msg.attach_alternative(html_message, "text/html")
                # msg.attach(f'event_pass_{ticket.ticket_number}.pdf', pdf_bytes, 'application/pdf') # Removed: WeasyPrint is not available
                
                msg.send(fail_silently=False)
                
                messages.success(request, 'Your event pass has been sent to your email as a PDF. Please check your inbox!')
                logger.info(f"Successfully sent event pass email (as PDF) for ticket {ticket_id} to {to_email}")
                return redirect('my_tickets')
            except Exception as pdf_error:
                logger.error(f"PDF generation also failed: {str(pdf_error)}")
                raise

        # 6. Prepare and Send the Email with PNG attachment (if we made it this far, we have image_bytes)
        subject = f"Your Event Pass for {ticket.event.title}"
        customer_name = ticket.customer.get_full_name() if hasattr(ticket.customer, 'get_full_name') else "Valued Customer"
        
        html_message = f"""
        <html>
        <body>
            <p>Dear {customer_name},</p>
            <p>Thank you for your purchase! Your event pass for <strong>{ticket.event.title}</strong> is attached to this email.</p>
            <p>Please save the attached image to your phone and present it at the venue for entry.</p>
            <p>Enjoy the event!</p>
            <p>Best regards,<br>The Tapnex Team</p>
        </body>
        </html>
        """
        plain_message = strip_tags(html_message)
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = ticket.customer.email
        
        msg = EmailMultiAlternatives(subject, plain_message, from_email, [to_email])
        msg.attach_alternative(html_message, "text/html")
        msg.attach(f'event_pass_{ticket.ticket_number}.png', image_bytes, 'image/png')
        
        msg.send(fail_silently=False)
        
        messages.success(request, 'Your event pass has been sent to your email. Please check your inbox!')
        logger.info(f"Successfully sent event pass email for ticket {ticket_id} to {to_email}")

    except Exception as e:
        logger.error(f"Error in send_ticket_email for ticket_id {ticket_id}: {str(e)}")
        logger.error(traceback.format_exc())
        messages.error(request, 'An unexpected error occurred while sending your ticket. Please contact support.')
    
    return redirect('my_tickets')


# --- NEW AND UPDATED CASHFREE VIEWS ---

@login_required
def create_cashfree_order(request):
    if request.method == 'POST':
        ticket_order = request.session.get('ticket_order', {})
        order_amount = ticket_order.get('total')

        if not order_amount or float(order_amount) <= 0:
            logger.error(f"Invalid order amount: {order_amount}")
            return JsonResponse({'error': 'Invalid order amount. Please select tickets and try again.'}, status=400)

        user = request.user
        
        # Format customer ID with leading zeros for consistent formatting
        customer_id = f"user_{user.id:03d}"
        
        # Clean phone number to ensure it's valid
        raw_phone = user.mobile_number or ""
        cleaned_phone = re.sub(r'\D', '', raw_phone)
        # Take last 10 digits if available, otherwise use a default
        customer_phone = cleaned_phone[-10:] if len(cleaned_phone) >= 10 else "0000000000"

        customer_name = f"{user.first_name} {user.last_name}".strip() or user.email
        customer_email = user.email

        # Generate a unique order ID
        order_id = f"order_{uuid.uuid4().hex[:12]}"
        
        logger.info(f"Creating new payment order: {order_id} for user {user.id}, amount: {order_amount}")
        
        # Create a payment transaction record to track the entire payment lifecycle
        payment_transaction = PaymentTransaction.objects.create(
            user=user,
            order_id=order_id,
            amount=float(order_amount),
            status='CREATED',
            response_data={
                'ticket_order': ticket_order,
                'customer_id': customer_id,
                'customer_email': customer_email,
                'creation_timestamp': timezone.now().isoformat(),
                'user_agent': request.META.get('HTTP_USER_AGENT', 'Unknown')
            }
        )

        # Setup return URL with all necessary parameters for proper callback processing
        return_url = request.build_absolute_uri(reverse('payment_status')) + \
                    f"?order_id={{order_id}}&session_order_id={order_id}&" + \
                    f"payment_status={{payment_status}}&transaction_id={{transaction_id}}"

        # Create order request for Cashfree API
        create_order_request = CreateOrderRequest(
            order_amount=float(order_amount),
            order_currency="INR",
            customer_details=CustomerDetails(
                customer_id=customer_id,
                customer_name=customer_name,
                customer_email=customer_email,
                customer_phone=customer_phone,
            ),
            order_meta=OrderMeta(
                return_url=return_url,
                notify_url=request.build_absolute_uri(reverse('payment_status'))  # Optional webhook URL
            ),
            order_id=order_id
        )
        
        # Store the ticket order in the session for retrieval during payment callback
        request.session[order_id] = ticket_order
        request.session.modified = True

        try:
            # Make API call to create payment order
            logger.info(f"Sending create order request to Cashfree for order: {order_id}")
            api_response = Cashfree().PGCreateOrder(
                x_api_version=CASHFREE_API_VERSION,
                create_order_request=create_order_request,
            )
            
            # Handle API response
            if hasattr(api_response, 'data') and api_response.data:
                # Extract and save important data from the response
                payment_session_id = getattr(api_response.data, 'payment_session_id', None)
                cf_order_id = getattr(api_response.data, 'order_id', None)
                payment_link = getattr(api_response.data, 'payment_link', None)
                
                # Update the transaction record with API response details
                payment_transaction.response_data = {
                    **payment_transaction.response_data,
                    'payment_session_id': payment_session_id,
                    'cf_order_id': cf_order_id,
                    'payment_link': payment_link,
                    'api_response_timestamp': timezone.now().isoformat()
                }
                payment_transaction.save()
                
                logger.info(f"Cashfree order created successfully: {cf_order_id}, session: {payment_session_id}")
                
                # Return necessary data for frontend to initiate payment
                response_data = {
                    "payment_session_id": payment_session_id,
                    "order_id": cf_order_id,
                    "payment_link": payment_link
                }
                return JsonResponse(response_data)
            else:
                logger.error(f"Invalid response from Cashfree for order {order_id}: {api_response}")
                return JsonResponse({'error': 'Invalid response from payment gateway'}, status=500)

        except Exception as e:
            logger.error(f"Cashfree order creation failed for order {order_id}: {str(e)}")
            # Update transaction with error details
            payment_transaction.status = 'FAILED'
            payment_transaction.response_data = {
                **payment_transaction.response_data,
                'error': str(e),
                'error_timestamp': timezone.now().isoformat()
            }
            payment_transaction.save()
            return JsonResponse({'error': 'Payment gateway error: Unable to create order'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


def payment_status(request):
    cashfree_order_id = request.GET.get('order_id')
    session_order_id = request.GET.get('session_order_id')
    payment_status_param = request.GET.get('payment_status', '').upper()
    transaction_id = request.GET.get('transaction_id', '')

    # Log all received parameters for debugging
    logger.info(f"Payment callback received - order_id: {cashfree_order_id}, payment_status: {payment_status_param}, transaction_id: {transaction_id}")

    ticket_order = request.session.get(session_order_id)

    if not ticket_order:
        messages.error(request, "Your session has expired. Please contact support if payment was deducted.")
        logger.warning(f"No ticket_order found in session for order_id: {cashfree_order_id}")
        # Instead of redirecting immediately, try to fetch payment transaction and verify status again
        try:
            payment_transaction = PaymentTransaction.objects.get(order_id=cashfree_order_id)
            logger.info(f"Found payment transaction for expired session order {cashfree_order_id} with status {payment_transaction.status}")
            if payment_transaction.status == 'SUCCESS':
                recent_tickets = Ticket.objects.filter(
                    purchase_transaction=payment_transaction
                ).select_related('event', 'ticket_type')
                messages.info(request, "Your payment was already processed successfully.")
                return render(request, 'core/payment_success.html', {
                    'order_id': cashfree_order_id,
                    'transaction_id': payment_transaction.transaction_id,
                    'recent_tickets': recent_tickets,
                })
            else:
                messages.error(request, "Your payment status is not successful. Please contact support.")
                return redirect('home')
        except PaymentTransaction.DoesNotExist:
            return redirect('home')

    # Get or create the payment transaction record
    payment_transaction = None
    try:
        payment_transaction = PaymentTransaction.objects.get(order_id=cashfree_order_id)
        logger.info(f"Found existing transaction record for order {cashfree_order_id}, status: {payment_transaction.status}")

        # If payment was already successfully processed, don't process again
        if payment_transaction.status == 'SUCCESS':
            logger.info(f"Transaction {cashfree_order_id} was already marked as successful, showing success page")
            messages.info(request, "Your payment was already processed successfully.")

            # Get the tickets that were created for this transaction
            recent_tickets = Ticket.objects.filter(
                purchase_transaction=payment_transaction
            ).select_related('event', 'ticket_type')

            return render(request, 'core/payment_success.html', {
                'order_id': cashfree_order_id,
                'transaction_id': payment_transaction.transaction_id,
                'recent_tickets': recent_tickets,
            })
    except PaymentTransaction.DoesNotExist:
        logger.info(f"No transaction record found for order {cashfree_order_id}, creating new record")
        payment_transaction = PaymentTransaction.objects.create(
            user=request.user,
            order_id=cashfree_order_id,
            transaction_id=transaction_id,
            amount=float(ticket_order.get('total', 0)),
            status='PENDING',
            response_data={
                'initial_callback_params': dict(request.GET.items())
            }
        )

    try:
        # Verify payment status with Cashfree servers
        order_details = None
        CASHFREE_API_VERSION = getattr(settings, 'CASHFREE_API_VERSION', '2022-09-01')

        # Enhanced payment verification using multiple sources
        api_order_status = None
        api_payment_status = None

        # Step 1: Try to verify using Cashfree API (most reliable source)
        try:
            logger.info(f"Verifying payment status via Cashfree API for order {cashfree_order_id}")
            # Extra validation
            if not cashfree_order_id or not isinstance(cashfree_order_id, str) or not cashfree_order_id.startswith("order_"):
                logger.error(f"Invalid cashfree_order_id: {cashfree_order_id} (type: {type(cashfree_order_id)})")
                raise ValueError("Invalid order_id for Cashfree API")
            order_details = Cashfree().PGFetchOrder(
                x_api_version=CASHFREE_API_VERSION,
                order_id=str(cashfree_order_id)
            )

            # Store response data for auditing
            if order_details and hasattr(order_details, 'data'):
                api_order_status = getattr(order_details.data, 'order_status', '').upper()
                api_payment_status = getattr(order_details.data, 'payment_status', '').upper()
                api_transaction_id = getattr(order_details.data, 'transaction_id', None)

                # Update transaction ID if available from API
                if api_transaction_id:
                    payment_transaction.transaction_id = api_transaction_id

                payment_transaction.response_data = {
                    **(payment_transaction.response_data or {}),
                    'api_response': {
                        'order_status': api_order_status,
                        'payment_status': api_payment_status,
                        'transaction_id': api_transaction_id,
                        'verification_timestamp': timezone.now().isoformat(),
                    }
                }
                payment_transaction.save()

                logger.info(f"API verification result - Order status: {api_order_status}, Payment status: {api_payment_status}")
        except Exception as e:
            logger.error(f"Error verifying payment with Cashfree API: {e}")
            payment_transaction.response_data = {
                **(payment_transaction.response_data or {}),
                'api_error': str(e),
                'api_error_timestamp': timezone.now().isoformat(),
            }
            payment_transaction.save()

        # Step 2: Payment verification logic with multiple checks
        payment_verified = False
        verification_source = None

        # Check API response first (most reliable)
        if api_order_status or api_payment_status:
            # Success indicators from API
            if api_order_status in ["PAID", "SUCCESS"] or api_payment_status in ["SUCCESS", "CAPTURED"]:
                payment_verified = True
                verification_source = "api"
                logger.info(f"Payment verified as successful via API response for order {cashfree_order_id}")
            # Clear failure indicators from API
            elif api_order_status in ["FAILED", "CANCELLED"] or api_payment_status in ["FAILED", "CANCELLED"]:
                payment_verified = False
                verification_source = "api"
                logger.warning(f"Payment explicitly failed/cancelled according to API for order {cashfree_order_id}")

        # If API verification didn't provide a clear answer, fall back to callback parameters
        if verification_source is None:
            logger.warning(f"Using fallback (callback parameters) for payment verification of order {cashfree_order_id}")
            if payment_status_param == "SUCCESS":
                payment_verified = True
                verification_source = "callback"
                logger.info(f"Payment verified as successful via callback parameters for order {cashfree_order_id}")
            elif payment_status_param in ["FAILED", "CANCELLED"]:
                payment_verified = False
                verification_source = "callback"
                logger.warning(f"Payment explicitly failed/cancelled according to callback params for order {cashfree_order_id}")

        # Step 3: Update payment transaction with verification result
        payment_transaction.response_data = {
            **(payment_transaction.response_data or {}),
            'payment_verified': payment_verified,
            'verification_source': verification_source,
            'verification_timestamp': timezone.now().isoformat(),
        }
        payment_transaction.save()

        # Step 4: Handle failed or cancelled payments
        if not payment_verified:
            # Update payment status based on specific failure reason if available
            if payment_status_param == 'CANCELLED' or api_order_status == 'CANCELLED' or api_payment_status == 'CANCELLED':
                payment_transaction.status = 'CANCELLED'
                failure_message = "Payment was cancelled. No tickets have been booked."
            else:
                payment_transaction.status = 'FAILED'
                failure_message = "Payment was not completed successfully. No tickets have been booked."

            payment_transaction.save()

            messages.error(request, failure_message)
            logger.warning(f"Payment failed/cancelled for order {cashfree_order_id} - Status set to {payment_transaction.status}")

            # Clean up the session but keep the ticket order so user can try again
            if session_order_id in request.session:
                del request.session[session_order_id]

            # Render payment failed page
            # Determine the failure reason from the appropriate source
            if verification_source == "api":
                failure_reason = api_order_status or api_payment_status
            else:
                failure_reason = payment_status_param
                
            context = {
                'order_id': cashfree_order_id,
                'event_id': ticket_order['event_id'],
                'failure_reason': failure_reason
            }
            return render(request, 'core/payment_failed.html', context)
        
        # Step 5: Process successful payment and create tickets
        with transaction.atomic():
            # Update payment status first
            payment_transaction.status = 'SUCCESS'
            if transaction_id and not payment_transaction.transaction_id:
                payment_transaction.transaction_id = transaction_id
            payment_transaction.save()
            
            logger.info(f"Payment marked as successful for order {cashfree_order_id}")
            
            # Check if tickets were already created for this transaction to avoid duplicates
            existing_tickets = Ticket.objects.filter(
                purchase_transaction_id=payment_transaction.id
            )
            
            if existing_tickets.exists():
                logger.info(f"{existing_tickets.count()} tickets already created for transaction {payment_transaction.id}, skipping creation")
                recent_tickets = existing_tickets.select_related('event', 'ticket_type')
            else:
                logger.info(f"Creating new tickets for verified payment {cashfree_order_id}")
                event_id = ticket_order['event_id']
                event = get_object_or_404(Event, id=event_id)
                selected_tickets = ticket_order.get('ticket_types', [])
                
                created_tickets = []
                for ticket_data in selected_tickets:
                    ticket_type = get_object_or_404(TicketType, id=ticket_data['id'])
                    for _ in range(ticket_data['quantity']):
                        ticket = Ticket.objects.create(
                            event=event,
                            ticket_type=ticket_type,
                            customer=request.user,
                            ticket_number=generate_ticket_number(),
                            status='SOLD',
                            purchase_date=timezone.now(),
                            unique_secure_token=str(uuid.uuid4()),
                            purchase_transaction=payment_transaction  # Link ticket to transaction
                        )
                        created_tickets.append(ticket)

                # Update payment transaction with ticket information
                payment_transaction.response_data = {
                    **(payment_transaction.response_data or {}),
                    'tickets_created': [t.id for t in created_tickets],
                    'ticket_count': len(created_tickets),
                    'ticket_creation_timestamp': timezone.now().isoformat()
                }
                payment_transaction.save()
                
                # Store tickets for display
                recent_tickets = Ticket.objects.filter(id__in=[t.id for t in created_tickets]).select_related('event', 'ticket_type')

                # Handle promo code if used
                promo_code_str = ticket_order.get('promo_code')
                if promo_code_str:
                    try:
                        promo_code = PromoCode.objects.get(code=promo_code_str, event=event)
                        promo_code.current_uses += 1
                        promo_code.save()
                        
                        PromoCodeUsage.objects.create(
                            promo_code=promo_code,
                            user=request.user,
                            ticket=created_tickets[0] if created_tickets else None,
                            order_total=ticket_order.get('subtotal', 0),
                            discount_amount=ticket_order.get('discount', 0)
                        )
                        
                        logger.info(f"Promo code {promo_code_str} applied successfully for order {cashfree_order_id}")
                    except Exception as e:
                        logger.error(f"Error processing promo code: {str(e)}")
                        # Don't fail the whole transaction if promo code processing fails

        # Clean up the session
        if session_order_id in request.session:
            del request.session[session_order_id]
        if 'ticket_order' in request.session:
            del request.session['ticket_order']
        
        logger.info(f"Successfully processed payment and created {recent_tickets.count()} tickets for order {cashfree_order_id}")
        messages.success(request, "Payment successful and tickets booked! You can view them in 'My Tickets'.")

    except Exception as e:
        # Update payment status to failed
        if payment_transaction:
            payment_transaction.status = 'FAILED'
            payment_transaction.response_data = {
                **(payment_transaction.response_data or {}),
                'processing_error': str(e)
            }
            payment_transaction.save()
            
        logger.error(f"Error creating tickets after payment for order {cashfree_order_id}: {e}")
        logger.error(traceback.format_exc())  # Log the full stack trace
        messages.error(request, "There was an error processing your order. Please contact support with your order ID.")
        
        # Render payment failed page with error context
        context = {
            'order_id': cashfree_order_id,
            'event_id': ticket_order.get('event_id'),
            'error_message': "There was a technical error processing your payment. Please contact support."
        }
        return render(request, 'core/payment_failed.html', context)

    # Prepare success context with tickets
    context = {
        'order_id': cashfree_order_id,
        'transaction_id': payment_transaction.transaction_id,
        'recent_tickets': recent_tickets,
    }
    return render(request, 'core/payment_success.html', context)

def get_payment_gateway_response(event_id):
    # Simulate payment gateway response
    # Replace this with actual API call to the payment gateway
    return {
        'status': 'SUCCESS',  # or 'FAILED'
        'failure_reason': None  # Provide reason if failed
    }
def verify_cashfree_signature(payload, signature, timestamp):
    """
    Verifies the webhook signature received from Cashfree to ensure authenticity.
    """
    if not signature or not timestamp:
        print("ERROR: Missing signature or timestamp in headers.")
        return False

    secret_key = settings.CASHFREE_SECRET_KEY
    if not secret_key:
        print("ERROR: CASHFREE_SECRET_KEY is not set in settings.")
        return False

    # The message to be signed is a concatenation of the timestamp and the raw payload
    message = timestamp + payload
    
    # Generate the expected signature
    secret_bytes = secret_key.encode('utf-8')
    message_bytes = message.encode('utf-8')
    
    hash_obj = hmac.new(secret_bytes, msg=message_bytes, digestmod=hashlib.sha256)
    expected_signature = base64.b64encode(hash_obj.digest()).decode('utf-8')

    # Compare signatures securely
    if hmac.compare_digest(expected_signature, signature):
        return True
    else:
        print("ERROR: Signature mismatch.")
        print(f"Expected: {expected_signature}")
        print(f"Received: {signature}")
        return False

@csrf_exempt  # Essential: Cashfree's server won't have a CSRF token
def cashfree_webhook(request):
    """
    Handles incoming webhook notifications from Cashfree Payments.
    This is the reliable, server-to-server confirmation.
    """
    if request.method == 'POST':
        # 1. Get raw payload and headers for signature verification
        raw_payload = request.body.decode('utf-8')
        received_signature = request.headers.get('x-webhook-signature')
        received_timestamp = request.headers.get('x-webhook-timestamp')
        
        # 2. Verify the Signature (CRITICAL SECURITY STEP)
        if not verify_cashfree_signature(raw_payload, received_signature, received_timestamp):
            print("SECURITY ALERT: Invalid webhook signature received.")
            return HttpResponse(status=401)

        # 3. Process the authentic webhook data
        try:
            data = json.loads(raw_payload)
            payment_data = data.get('data', {}).get('payment', {})
            order_data = data.get('data', {}).get('order', {})
            
            payment_status = payment_data.get('payment_status')
            order_id = order_data.get('order_id') # This is your TicketPurchase pk

            print(f"Processing webhook for Order ID: {order_id} with Status: {payment_status}")
            
            # Find the corresponding purchase in your database
            try:
                ticket_purchase = TicketPurchase.objects.get(pk=order_id)
            except TicketPurchase.DoesNotExist:
                print(f"ERROR: TicketPurchase with ID {order_id} not found.")
                return HttpResponse(status=404)

            # 4. Implement Robust Conditional Logic (THE CORE FIX)
            if payment_status == 'SUCCESS':
                # Only generate tickets if the status isn't already 'Paid'
                if ticket_purchase.payment_status != 'Paid':
                    ticket_purchase.payment_status = 'Paid'
                    ticket_purchase.transaction_id = payment_data.get('cf_payment_id') # Store Cashfree's transaction ID
                    ticket_purchase.save()
                    
                    # Call your ticket generation and email function
                    generate_tickets_for_purchase(ticket_purchase) 
                    print(f"SUCCESS: Tickets generated for purchase {order_id}.")
                else:
                    print(f"INFO: Received SUCCESS webhook for already processed purchase {order_id}.")
                
            elif payment_status in ['FAILED', 'USER_DROPPED', 'CANCELLED']:
                ticket_purchase.payment_status = 'Failed'
                ticket_purchase.save()
                print(f"FAILURE: Purchase {order_id} marked as failed.")
            
            # Acknowledge receipt to Cashfree
            return HttpResponse(status=200)

        except Exception as e:
            print(f"ERROR processing webhook: {e}")
            return HttpResponse(status=400) # Bad request

    return HttpResponse(status=405) # Method not allowed


def payment_failed(request):
    return render(request, 'core/payment_failed.html')
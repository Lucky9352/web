from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponse
from django.contrib import messages
import csv

from .models import Event, TicketType, User, Ticket, PromoCode, EventStaff, PromoCodeUsage, EventSponsor
from .forms import (
    EventForm, AdminUserCreationForm, TicketForm, PromoCodeForm,
    EventStaffForm, TicketTypeForm, EventSponsorFormSet
)
from .utils import handle_event_csv_upload, generate_sample_csv

def is_admin(user):
    return user.is_authenticated and user.role == 'ADMIN'

@login_required
@user_passes_test(is_admin)
def admin_delete_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    event.delete()
    messages.success(request, 'Event deleted successfully!')
    return redirect('admin_event_list')

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    # Basic stats
    total_users = User.objects.count()
    total_events = Event.objects.count()
    total_tickets = Ticket.objects.count()
    active_users = User.objects.filter(is_active=True).count()

    # Recent events (last 5)
    events = Event.objects.order_by('-created_at')[:5]
    
    # Recent users (last 5)
    users = User.objects.order_by('-date_joined')[:5]

    context = {
        'total_users': total_users,
        'total_events': total_events,
        'total_tickets': total_tickets,
        'active_users': active_users,
        'events': events,
        'users': users,
        'user': request.user,
    }
    return render(request, 'core/admin_dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def admin_create_event(request):
    if request.method == 'POST':
        if 'csv_file' in request.FILES:
            csv_file = request.FILES['csv_file']
            # Accept any file as CSV (rely on content rather than extension)
            # This allows users to upload .txt files or other formats containing CSV data
            
            try:
                success, message, event_id = handle_event_csv_upload(csv_file, request.user)
                if success:
                    messages.success(request, message)
                    return redirect('admin_edit_event', event_id=event_id)
                else:
                    messages.error(request, message)
                    return redirect('admin_create_event')
            except Exception as e:
                messages.error(request, f"Error processing file: {str(e)}")
                return redirect('admin_create_event')
        else:
            form = EventForm(request.POST, request.FILES)
            sponsor_formset = EventSponsorFormSet(request.POST, prefix='sponsors')
            
            if form.is_valid() and sponsor_formset.is_valid():
                event = form.save(commit=False)
                event.organizer = request.user
                event.save()
                
                # Save sponsors
                sponsor_formset.instance = event
                sponsor_formset.save()
                
                # Calculate total capacity from ticket quantities
                total_capacity = 0
                
                # Save ticket types
                for i in range(1, 5):  # Handle up to 4 ticket types
                    ticket_type = request.POST.get(f'ticket_type_{i}')
                    if ticket_type:  # If a ticket type name is provided
                        try:
                            price = request.POST.get(f'ticket_price_{i}', '0')
                            quantity = request.POST.get(f'ticket_quantity_{i}', '0')
                            
                            # Convert values with error handling
                            try:
                                price_value = float(price) if price else 0
                            except ValueError:
                                price_value = 0
                                
                            try:
                                quantity_value = int(quantity) if quantity else 0
                            except ValueError:
                                quantity_value = 0
                                
                            total_capacity += quantity_value
                            
                            TicketType.objects.create(
                                event=event,
                                type_name=ticket_type,
                                price=price_value,
                                quantity=quantity_value,
                                description=request.POST.get(f'ticket_description_{i}', '')
                            )
                        except Exception as e:
                            messages.warning(request, f"Issue with ticket type {i}: {str(e)}")
                
                # Ensure at least one ticket type exists
                if not event.ticket_types.exists():
                    TicketType.objects.create(
                        event=event,
                        type_name="General Admission",
                        price=0.00,
                        quantity=event.capacity or 100,
                        description="Default ticket type"
                    )
                    messages.info(request, "Created default ticket type for this event.")
                
                # Update event capacity if needed
                if total_capacity > 0:
                    event.capacity = total_capacity
                    event.save()
                    
                messages.success(request, 'Event created successfully!')
                return redirect('admin_event_list')
            else:
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
                
                if not sponsor_formset.is_valid():
                    messages.error(request, 'Please check the sponsor information.')
    else:
        form = EventForm()
        sponsor_formset = EventSponsorFormSet(prefix='sponsors')
    
    return render(request, 'core/admin/event_form.html', {
        'form': form,
        'sponsor_formset': sponsor_formset,
        'action': 'Create'
    })

@login_required
@user_passes_test(is_admin)
def admin_event_list(request):
    events = Event.objects.all().order_by('-created_at')
    return render(request, 'core/admin/event_list.html', {'events': events})

@login_required
@user_passes_test(is_admin)
def admin_edit_event(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    if request.method == 'POST':
        form = EventForm(request.POST, request.FILES, instance=event)
        sponsor_formset = EventSponsorFormSet(request.POST, instance=event, prefix='sponsors')
        
        if form.is_valid() and sponsor_formset.is_valid():
            event = form.save()
            
            # Save sponsors
            sponsor_formset.save()
            
            messages.success(request, 'Event updated successfully!')
            return redirect('admin_event_list')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
            
            if not sponsor_formset.is_valid():
                messages.error(request, 'Please check the sponsor information.')
    else:
        form = EventForm(instance=event)
        sponsor_formset = EventSponsorFormSet(instance=event, prefix='sponsors')
    
    return render(request, 'core/admin/event_form.html', {
        'form': form,
        'sponsor_formset': sponsor_formset,
        'action': 'Edit',
        'event': event
    })

# User Management Views
@login_required
@user_passes_test(is_admin)
def admin_user_list(request):
    users = User.objects.all().order_by('-date_joined')
    return render(request, 'core/admin/user_list.html', {'users': users})

@login_required
@user_passes_test(is_admin)
def admin_create_user(request):
    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST, request.FILES)
        if form.is_valid():
            user = form.save(commit=False)
            # Set role from form
            user.role = form.cleaned_data['role']
            user.save()
            messages.success(request, f'User created successfully with {user.get_role_display()} role!')
            return redirect('admin_user_list')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = AdminUserCreationForm()
    return render(request, 'core/admin/user_form.html', {'form': form, 'action': 'Create'})

@login_required
@user_passes_test(is_admin)
def admin_edit_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        # Use custom form for handling password fields
        form = AdminUserCreationForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            updated_user = form.save(commit=False)
            # Set role from form
            updated_user.role = form.cleaned_data['role']
            
            # Check if password has been provided
            if form.cleaned_data.get('password1') and form.cleaned_data.get('password2'):
                # Password is being changed
                pass  # password will be set by form.save()
            else:
                # Keep existing password
                updated_user.password = user.password
                
            updated_user.save()
            messages.success(request, f'User updated successfully with {updated_user.get_role_display()} role!')
            return redirect('admin_user_list')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = AdminUserCreationForm(instance=user)
    
    return render(request, 'core/admin/user_form.html', {'form': form, 'action': 'Edit'})

@login_required
@user_passes_test(is_admin)
def admin_delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if user.id != request.user.id:
        user.delete()
        messages.success(request, 'User deleted successfully!')
    else:
        messages.error(request, 'You cannot delete your own account!')
    return redirect('admin_user_list')

# Ticket Management Views
@login_required
@user_passes_test(is_admin)
def admin_ticket_list(request):
    tickets = Ticket.objects.all().order_by('-purchase_date')
    return render(request, 'core/admin/ticket_list.html', {'tickets': tickets})

@login_required
@user_passes_test(is_admin)
def admin_create_ticket(request):
    if request.method == 'POST':
        form = TicketForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Ticket created successfully!')
            return redirect('admin_ticket_list')
    else:
        form = TicketForm()
    return render(request, 'core/admin/ticket_form.html', {'form': form, 'action': 'Create'})

@login_required
@user_passes_test(is_admin)
def admin_edit_ticket(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    if request.method == 'POST':
        form = TicketForm(request.POST, instance=ticket)
        if form.is_valid():
            form.save()
            messages.success(request, 'Ticket updated successfully!')
            return redirect('admin_ticket_list')
    else:
        form = TicketForm(instance=ticket)
    return render(request, 'core/admin/ticket_form.html', {'form': form, 'action': 'Edit'})

@login_required
@user_passes_test(is_admin)
def admin_delete_ticket(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    ticket.delete()
    messages.success(request, 'Ticket deleted successfully!')
    return redirect('admin_ticket_list')

# Promo Code Management Views
@login_required
@user_passes_test(is_admin)
def admin_promo_code_list(request):
    promo_codes = PromoCode.objects.all().order_by('-created_at')
    return render(request, 'core/admin/promo_code_list.html', {'promo_codes': promo_codes})

@login_required
@user_passes_test(is_admin)
def admin_create_promo_code(request):
    if request.method == 'POST':
        form = PromoCodeForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Promo code created successfully!')
            return redirect('admin_promo_code_list')
    else:
        form = PromoCodeForm()
    return render(request, 'core/admin/promo_code_form.html', {'form': form, 'action': 'Create'})

@login_required
@user_passes_test(is_admin)
def admin_edit_promo_code(request, code_id):
    promo_code = get_object_or_404(PromoCode, id=code_id)
    if request.method == 'POST':
        form = PromoCodeForm(request.POST, instance=promo_code)
        if form.is_valid():
            form.save()
            messages.success(request, 'Promo code updated successfully!')
            return redirect('admin_promo_code_list')
    else:
        form = PromoCodeForm(instance=promo_code)
    return render(request, 'core/admin/promo_code_form.html', {'form': form, 'action': 'Edit'})

@login_required
@user_passes_test(is_admin)
def admin_delete_promo_code(request, code_id):
    promo_code = get_object_or_404(PromoCode, id=code_id)
    promo_code.delete()
    messages.success(request, 'Promo code deleted successfully!')
    return redirect('admin_promo_code_list')

# Staff Management Views
@login_required
@user_passes_test(is_admin)
def admin_staff_list(request):
    staff = EventStaff.objects.all().order_by('-assigned_at')
    return render(request, 'core/admin/staff_list.html', {'staff': staff})

@login_required
@user_passes_test(is_admin)
def admin_create_staff(request):
    if request.method == 'POST':
        form = EventStaffForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Staff member created successfully!')
            return redirect('admin_staff_list')
    else:
        form = EventStaffForm()
    return render(request, 'core/admin/staff_form.html', {'form': form, 'action': 'Create'})

@login_required
@user_passes_test(is_admin)
def admin_edit_staff(request, staff_id):
    staff = get_object_or_404(EventStaff, id=staff_id)
    if request.method == 'POST':
        form = EventStaffForm(request.POST, instance=staff)
        if form.is_valid():
            form.save()
            messages.success(request, 'Staff member updated successfully!')
            return redirect('admin_staff_list')
    else:
        form = EventStaffForm(instance=staff)
    return render(request, 'core/admin/staff_form.html', {'form': form, 'action': 'Edit'})

@login_required
@user_passes_test(is_admin)
def admin_delete_staff(request, staff_id):
    staff = get_object_or_404(EventStaff, id=staff_id)
    staff.delete()
    messages.success(request, 'Staff member deleted successfully!')
    return redirect('admin_staff_list')

# Ticket Type Management Views
@login_required
@user_passes_test(is_admin)
def admin_ticket_type_list(request):
    ticket_types = TicketType.objects.all().order_by('event', 'type_name')
    events = Event.objects.all().order_by('title')
    return render(request, 'core/admin/ticket_type_list.html', {
        'ticket_types': ticket_types,
        'events': events
    })

@login_required
@user_passes_test(is_admin)
def admin_create_ticket_type(request):
    # Check if event_id is provided in GET parameters
    event_id = request.GET.get('event_id')
    event = None
    
    # If event_id is provided, get the event
    if event_id:
        event = get_object_or_404(Event, id=event_id)
        
    if request.method == 'POST':
        form = TicketTypeForm(request.POST, request.FILES)
        if form.is_valid():
            ticket_type = form.save(commit=False)
            
            # Template handling removed
            
            ticket_type.save()
            messages.success(request, 'Ticket type created successfully!')
            
            # If created from event form, redirect back to event edit
            if event_id:
                return redirect('admin_edit_event', event_id=event_id)
            else:
                return redirect('admin_ticket_type_list')
    else:
        # Pre-populate the event field if event_id is provided
        initial_data = {}
        if event:
            initial_data = {'event': event}
        
        form = TicketTypeForm(initial=initial_data)
    
    return render(request, 'core/admin/ticket_type_form.html', {
        'form': form, 
        'action': 'Create',
        'event': event
    })

@login_required
@user_passes_test(is_admin)
def admin_edit_ticket_type(request, type_id):
    ticket_type = get_object_or_404(TicketType, id=type_id)
    if request.method == 'POST':
        form = TicketTypeForm(request.POST, request.FILES, instance=ticket_type)
        if form.is_valid():
            updated_ticket_type = form.save(commit=False)
            
            # Template handling removed
            
            updated_ticket_type.save()
            messages.success(request, 'Ticket type updated successfully!')
            return redirect('admin_ticket_type_list')
    else:
        form = TicketTypeForm(instance=ticket_type)
    
    return render(request, 'core/admin/ticket_type_form.html', {
        'form': form, 
        'action': 'Edit',
        'ticket_type': ticket_type
    })

@login_required
@user_passes_test(is_admin)
def admin_delete_ticket_type(request, type_id):
    ticket_type = get_object_or_404(TicketType, id=type_id)
    ticket_type.delete()
    messages.success(request, 'Ticket type deleted successfully!')
    return redirect('admin_ticket_type_list')
    



# API Endpoints for Event and Ticket Type Management
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
import json
import os
from django.conf import settings
from django.core.files.storage import default_storage

@login_required
@user_passes_test(is_admin)
@require_http_methods(["POST"])
def api_create_event(request):
    try:
        # Parse JSON data from request body
        data = json.loads(request.body)
        
        # Create new Event instance
        event = Event(
            title=data.get('title'),
            description=data.get('description'),
            short_description=data.get('short_description', ''),
            date=data.get('date'),
            end_date=data.get('end_date'),
            time=data.get('time'),
            end_time=data.get('end_time'),
            venue=data.get('venue'),
            venue_address=data.get('venue_address', ''),
            venue_map_link=data.get('venue_map_link', ''),
            capacity=data.get('capacity', 0),
            event_type=data.get('event_type', ''),
            registration_deadline=data.get('registration_deadline'),
            organizer=request.user,
            status=data.get('status', 'DRAFT'),
            featured=data.get('featured', False),
            venue_terms=data.get('venue_terms', ''),
            event_terms=data.get('event_terms', ''),
            restrictions=data.get('restrictions', '')
        )
        
        # Handle banner image if included in multipart form data
        if 'banner_image' in request.FILES:
            banner_image = request.FILES['banner_image']
            filename = f"event_{data.get('title').replace(' ', '_')}{os.path.splitext(banner_image.name)[1]}"
            path = os.path.join('event_banners', filename)
            default_storage.save(path, banner_image)
            event.banner_image = path
        
        event.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Event created successfully',
            'event_id': event.id
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error creating event: {str(e)}'
        }, status=400)

@login_required
@user_passes_test(is_admin)
@require_http_methods(["PUT", "PATCH"])
def api_update_event(request, event_id):
    try:
        event = get_object_or_404(Event, id=event_id)
        data = json.loads(request.body)
        
        # Update event fields if provided
        if 'title' in data:
            event.title = data['title']
        if 'description' in data:
            event.description = data['description']
        if 'short_description' in data:
            event.short_description = data['short_description']
        if 'date' in data:
            event.date = data['date']
        if 'end_date' in data:
            event.end_date = data['end_date']
        if 'time' in data:
            event.time = data['time']
        if 'end_time' in data:
            event.end_time = data['end_time']
        if 'venue' in data:
            event.venue = data['venue']
        if 'venue_address' in data:
            event.venue_address = data['venue_address']
        if 'venue_map_link' in data:
            event.venue_map_link = data['venue_map_link']
        if 'capacity' in data:
            event.capacity = data['capacity']
        if 'event_type' in data:
            event.event_type = data['event_type']
        if 'registration_deadline' in data:
            event.registration_deadline = data['registration_deadline']
        if 'status' in data:
            event.status = data['status']
        if 'featured' in data:
            event.featured = data['featured']
        if 'venue_terms' in data:
            event.venue_terms = data['venue_terms']
        if 'event_terms' in data:
            event.event_terms = data['event_terms']
        if 'restrictions' in data:
            event.restrictions = data['restrictions']
        
        # Handle banner image if included in multipart form data
        if 'banner_image' in request.FILES:
            # Delete old banner if exists
            if event.banner_image:
                old_path = event.banner_image.path
                if os.path.exists(old_path):
                    os.remove(old_path)
            
            banner_image = request.FILES['banner_image']
            filename = f"event_{event.id}_{event.title.replace(' ', '_')}{os.path.splitext(banner_image.name)[1]}"
            path = os.path.join('event_banners', filename)
            default_storage.save(path, banner_image)
            event.banner_image = path
        
        event.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Event updated successfully'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error updating event: {str(e)}'
        }, status=400)

@login_required
@user_passes_test(is_admin)
@require_http_methods(["POST"])
def api_create_ticket_type(request, event_id):
    try:
        event = get_object_or_404(Event, id=event_id)
        
        # Check if request is multipart form data or JSON
        if request.content_type and 'multipart/form-data' in request.content_type:
            # Create a form instance with POST data and FILES
            form_data = request.POST.copy()
            form_data['event'] = event.id  # Ensure the event is set
            
            form = TicketTypeForm(form_data, request.FILES)
            
            if form.is_valid():
                ticket_type = form.save()
                
                return JsonResponse({
                    'success': True,
                    'message': 'Ticket type created successfully',
                    'ticket_type_id': ticket_type.id,
                    'ticket_type': {
                        'id': ticket_type.id,
                        'type_name': ticket_type.type_name,
                        'price': float(ticket_type.price),
                        'quantity': ticket_type.quantity,
                        'attendees_per_ticket': ticket_type.attendees_per_ticket,

                    }
                })
            else:
                # Return form validation errors
                errors = dict([(key, [str(error) for error in errors_list]) 
                          for key, errors_list in form.errors.items()])
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid form data',
                    'errors': errors
                }, status=400)
        else:
            # Handle JSON data
            data = json.loads(request.body)
            data['event'] = event.id  # Ensure the event is set
            
            form = TicketTypeForm(data)
            if form.is_valid():
                ticket_type = form.save()
                
                return JsonResponse({
                    'success': True,
                    'message': 'Ticket type created successfully',
                    'ticket_type_id': ticket_type.id
                })
            else:
                # Return form validation errors
                errors = dict([(key, [str(error) for error in errors_list]) 
                          for key, errors_list in form.errors.items()])
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid form data',
                    'errors': errors
                }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error creating ticket type: {str(e)}'
        }, status=400)

@login_required
@user_passes_test(is_admin)
@require_http_methods(["PUT", "PATCH", "POST"])  # Allow POST for form submissions
def api_update_ticket_type(request, type_id):
    try:
        ticket_type = get_object_or_404(TicketType, id=type_id)
        
        # Check if request is multipart form data or JSON
        if request.content_type and 'multipart/form-data' in request.content_type:
            # For PATCH/PUT with form-data, we need to handle it specially
            if request.method in ['PATCH', 'PUT']:
                data = request.POST.copy()
                # Only update the fields that are provided
                instance_data = {
                    'event': ticket_type.event.id,
                    'type_name': ticket_type.type_name,
                    'price': ticket_type.price,
                    'quantity': ticket_type.quantity,
                    'description': ticket_type.description,
                    'attendees_per_ticket': ticket_type.attendees_per_ticket,
                    'image_template_url': ticket_type.image_template_url
                }
                
                # Update with provided data
                for key in data:
                    if key in instance_data and key != 'event':  # Don't allow changing event
                        instance_data[key] = data[key]
                
                form = TicketTypeForm(instance_data, request.FILES, instance=ticket_type)
            else:  # POST
                form = TicketTypeForm(request.POST, request.FILES, instance=ticket_type)
            
            if form.is_valid():
                updated_ticket_type = form.save()
                return JsonResponse({
                    'success': True,
                    'message': 'Ticket type updated successfully',
                    'ticket_type': {
                        'id': updated_ticket_type.id,
                        'type_name': updated_ticket_type.type_name,
                        'price': float(updated_ticket_type.price),
                        'quantity': updated_ticket_type.quantity,
                        'attendees_per_ticket': updated_ticket_type.attendees_per_ticket,

                    }
                })
            else:
                # Return form validation errors
                errors = dict([(key, [str(error) for error in errors_list]) 
                          for key, errors_list in form.errors.items()])
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid form data',
                    'errors': errors
                }, status=400)
        else:
            # Handle JSON data
            data = json.loads(request.body)
            instance_data = {
                'event': ticket_type.event.id
            }
            
            # Only update fields that are provided in the request
            if 'type_name' in data:
                instance_data['type_name'] = data['type_name']
            if 'price' in data:
                instance_data['price'] = data['price']
            if 'quantity' in data:
                instance_data['quantity'] = data['quantity']
            if 'description' in data:
                instance_data['description'] = data['description']
            if 'attendees_per_ticket' in data:
                instance_data['attendees_per_ticket'] = data['attendees_per_ticket']
            
            form = TicketTypeForm(instance_data, instance=ticket_type)
            
            if form.is_valid():
                updated_ticket_type = form.save()
                return JsonResponse({
                    'success': True,
                    'message': 'Ticket type updated successfully'
                })
            else:
                # Return form validation errors
                errors = dict([(key, [str(error) for error in errors_list]) 
                          for key, errors_list in form.errors.items()])
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid form data',
                    'errors': errors
                }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error updating ticket type: {str(e)}'
        }, status=400)

@login_required
@user_passes_test(is_admin)
def download_sample_csv(request):
    """Download instructions for CSV event creation as a text file."""
    response = HttpResponse(content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="csv_instructions.txt"'
    response['Cache-Control'] = 'no-cache'
    
    # Read the instructions from the markdown file
    import os
    from django.conf import settings
    
    instructions_path = os.path.join(settings.BASE_DIR, 'ticketing/static/core/docs/csv_upload_guide.md')
    detailed_instructions_path = os.path.join(settings.BASE_DIR, 'ticketing/static/core/docs/csv_instructions.md')
    
    try:
        with open(detailed_instructions_path, 'r', encoding='utf-8') as file:
            instructions = file.read()
    except FileNotFoundError:
        try:
            with open(instructions_path, 'r', encoding='utf-8') as file:
                instructions = file.read()
        except FileNotFoundError:
            instructions = "# CSV Upload Instructions\n\nPlease refer to the documentation for detailed instructions on how to format your CSV file."
    
    # Add a sample CSV content at the end of the instructions
    instructions += "\n\n## Sample CSV Content\n\n```csv\n"
    csv_content = generate_sample_csv()
    instructions += csv_content + "\n```"
    
    response.write(instructions)
    return response

# Promo Code Analytics Views
@login_required
@user_passes_test(is_admin)
def admin_promo_code_analytics(request):
    """Admin dashboard for promo code analytics"""
    promo_codes = PromoCode.objects.all().order_by('-created_at')
    
    # Enhance promo codes with analytics data
    for promo_code in promo_codes:
        promo_code.usage_count = promo_code.promo_code_usages.count()
        promo_code.tickets_booked = promo_code.total_tickets_booked()
        promo_code.amount_saved = promo_code.total_amount_saved()
        promo_code.revenue_generated = promo_code.total_revenue_generated()
        promo_code.average_order_value = promo_code.average_order_value()
        promo_code.redemption_rate = promo_code.redemption_rate()
    
    return render(request, 'core/admin/promo_code_analytics.html', {
        'promo_codes': promo_codes
    })

@login_required
def organizer_promo_code_analytics(request):
    """Organizer dashboard for promo code analytics for their events"""
    # Get events organized by this user
    events = Event.objects.filter(organizer=request.user)
    promo_codes = PromoCode.objects.filter(event__in=events).order_by('-created_at')
    
    # Enhance promo codes with analytics data
    for promo_code in promo_codes:
        promo_code.usage_count = promo_code.promo_code_usages.count()
        promo_code.tickets_booked = promo_code.total_tickets_booked()
        promo_code.amount_saved = promo_code.total_amount_saved()
        promo_code.revenue_generated = promo_code.total_revenue_generated()
        promo_code.average_order_value = promo_code.average_order_value()
        promo_code.redemption_rate = promo_code.redemption_rate()
    
    return render(request, 'core/organizer_promo_code_analytics.html', {
        'promo_codes': promo_codes
    })
    
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
                'attendees_per_ticket': ticket_type.attendees_per_ticket,
                'image_template_url': ticket_type.image_template_url or ''
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

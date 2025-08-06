from django.contrib.auth import views as auth_views
from django.urls import path
from . import views
from . import admin_views
from . import volunteer_views

urlpatterns = [
    path('', views.home, name='home'),
    path('contact/', views.contact, name='contact'),
    path('terms/', views.terms, name='terms'),
    path('refunds/', views.refunds, name='refunds'),
    path('privacy/', views.privacy, name='privacy'),
    path('signup/', views.signup, name='signup'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('login/', views.login_view, name='login'),
    path('logout/', auth_views.LogoutView.as_view(template_name='core/logout.html',next_page='home',http_method_names=['get', 'post']), name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('my-tickets/', views.my_tickets, name='my_tickets'),
    path('send-ticket-email/<int:ticket_id>/', views.send_ticket_email, name='send_ticket_email'),

    path('cashfree-webhook/', views.cashfree_webhook, name='cashfree_webhook'),
    path('payment-success/', views.payment_status, name='payment_success'),
    path('payment-failed/', views.payment_failed, name='payment_failed'),
    # Event related URLs
    path('events/', views.event_list, name='event_list'),
    path('events/create/', views.create_event, name='create_event'),
    path('events/<int:event_id>/', views.event_detail, name='event_detail'),
    path('events/<int:event_id>/checkout/', views.checkout, name='checkout'),
    path('events/<int:event_id>/purchase/', views.purchase_ticket, name='purchase_ticket'),
    path('api/event/<int:event_id>/ticket-types/', views.get_event_ticket_types, name='get_event_ticket_types'),
    path('events/<int:event_id>/book/', views.book_ticket, name='book_ticket'),
    path('events/<int:event_id>/process-payment/', views.process_payment, name='process_payment'),
    path('api/validate-promo/<str:code>/', views.validate_promo_code, name='validate_promo_code'),
    path('events/<int:event_id>/checkout/success/', views.checkout_success, name='checkout_success'),

    # Payment Gateway URLs
    path('create-cashfree-order/', views.create_cashfree_order, name='create_cashfree_order'),
    path('payment-status/', views.payment_status, name='payment_status'),

    # API Endpoints for Event and Ticket Type Management
    path('api/events/create/', admin_views.api_create_event, name='api_create_event'),
    path('api/events/<int:event_id>/update/', admin_views.api_update_event, name='api_update_event'),
    path('api/events/<int:event_id>/ticket-types/', admin_views.api_create_ticket_type, name='api_create_ticket_type'),
    path('api/events/<int:event_id>/ticket-types/list/', admin_views.api_get_event_ticket_types, name='api_get_event_ticket_types'),
    path('api/ticket-types/<int:type_id>/update/', admin_views.api_update_ticket_type, name='api_update_ticket_type'),

    # API Endpoints for Ticket Checkout and Download
    path('api/checkout/ticket/', views.api_checkout_ticket, name='api_checkout_ticket'),
    path('api/ticket/download/<int:ticket_id>/', views.api_download_ticket, name='api_download_ticket'),
    path('ticket/<int:ticket_id>/event-pass/', views.event_pass, name='event_pass'),

    # Volunteer ticket scanning
    path('volunteer/dashboard/', volunteer_views.volunteer_dashboard, name='volunteer_dashboard'),
    path('volunteer/scan/', volunteer_views.volunteer_scan_tickets, name='volunteer_scan_tickets'),
    path('api/validate-ticket/', volunteer_views.api_validate_ticket, name='api_validate_ticket'),

    # Password reset URLs
    path('password_reset/', auth_views.PasswordResetView.as_view(
        template_name='core/password_reset.html'
    ), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='core/password_reset_done.html'
    ), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='core/password_reset_confirm.html'
    ), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='core/password_reset_complete.html'
    ), name='password_reset_complete'),
    
    # Profile URLs
    path('profile/update/', views.update_profile, name='update_profile'),

    # Admin Dashboard URLs
    path('admin-panel/dashboard/', admin_views.admin_dashboard, name='admin_dashboard'),

    # Event Management
    path('admin-panel/events/', admin_views.admin_event_list, name='admin_event_list'),
    path('admin-panel/events/create/', admin_views.admin_create_event, name='admin_create_event'),
    path('admin-panel/events/<int:event_id>/edit/', admin_views.admin_edit_event, name='admin_edit_event'),
    path('admin-panel/events/<int:event_id>/delete/', admin_views.admin_delete_event, name='admin_delete_event'),

    # User Management
    path('admin-panel/users/', admin_views.admin_user_list, name='admin_user_list'),
    path('admin-panel/users/create/', admin_views.admin_create_user, name='admin_create_user'),
    path('admin-panel/users/<int:user_id>/edit/', admin_views.admin_edit_user, name='admin_edit_user'),
    path('admin-panel/users/<int:user_id>/delete/', admin_views.admin_delete_user, name='admin_delete_user'),

    # Ticket Management
    path('admin-panel/tickets/', admin_views.admin_ticket_list, name='admin_ticket_list'),
    path('admin-panel/tickets/create/', admin_views.admin_create_ticket, name='admin_create_ticket'),
    path('admin-panel/tickets/<int:ticket_id>/edit/', admin_views.admin_edit_ticket, name='admin_edit_ticket'),
    path('admin-panel/tickets/<int:ticket_id>/delete/', admin_views.admin_delete_ticket, name='admin_delete_ticket'),

    # Promo Code Management
    path('admin-panel/promo-codes/', admin_views.admin_promo_code_list, name='admin_promo_code_list'),
    path('admin-panel/promo-codes/create/', admin_views.admin_create_promo_code, name='admin_create_promo_code'),
    path('admin-panel/promo-codes/<int:code_id>/edit/', admin_views.admin_edit_promo_code, name='admin_edit_promo_code'),
    path('admin-panel/promo-codes/<int:code_id>/delete/', admin_views.admin_delete_promo_code, name='admin_delete_promo_code'),

    # Staff Management
    path('admin-panel/staff/', admin_views.admin_staff_list, name='admin_staff_list'),
    path('admin-panel/staff/create/', admin_views.admin_create_staff, name='admin_create_staff'),
    path('admin-panel/staff/<int:staff_id>/edit/', admin_views.admin_edit_staff, name='admin_edit_staff'),
    path('admin-panel/staff/<int:staff_id>/delete/', admin_views.admin_delete_staff, name='admin_delete_staff'),

    # Ticket Type Management
    path('admin-panel/ticket-types/', admin_views.admin_ticket_type_list, name='admin_ticket_type_list'),
    path('admin-panel/ticket-types/create/', admin_views.admin_create_ticket_type, name='admin_create_ticket_type'),
    path('admin-panel/ticket-types/<int:type_id>/edit/', admin_views.admin_edit_ticket_type, name='admin_edit_ticket_type'),
    path('admin-panel/ticket-types/<int:type_id>/delete/', admin_views.admin_delete_ticket_type, name='admin_delete_ticket_type'),

    # Promo Code Analytics
    path('admin-panel/promo-codes/analytics/', admin_views.admin_promo_code_analytics, name='admin_promo_code_analytics'),
    path('organizer/promo-codes/analytics/', admin_views.organizer_promo_code_analytics, name='organizer_promo_code_analytics'),

    path('admin-panel/events/download-sample-csv/', admin_views.download_sample_csv, name='download_sample_csv'),
    path('download-csv-guide/', views.download_csv_guide, name='download_csv_guide'),
]
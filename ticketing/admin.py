from django.contrib import admin
from .models import Event, Ticket, PromoCode, EventStaff, User, TicketType, PaymentTransaction

@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ('title', 'date', 'venue', 'capacity', 'status', 'featured')
    list_filter = ('status', 'featured', 'date')
    search_fields = ('title', 'description', 'venue')
    prepopulated_fields = {'slug': ('title',)}
    readonly_fields = ('created_at', 'updated_at')
    list_editable = ('status', 'featured')
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'slug', 'description', 'short_description', 'banner_image')
        }),
        ('Event Details', {
            'fields': ('date', 'end_date', 'time', 'end_time', 'venue', 'venue_address', 'venue_map_link')
        }),
        ('Event Settings', {
            'fields': ('capacity', 'registration_deadline')
        }),
        ('Organization', {
            'fields': ('organizer', 'status', 'featured')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('ticket_number', 'event', 'ticket_type', 'customer', 'status', 'purchase_date')
    list_filter = ('status', 'event', 'purchase_date', 'ticket_type')
    search_fields = ('ticket_number', 'customer__email', 'event__title')
    readonly_fields = ('purchase_date',)

@admin.register(PromoCode)
class PromoCodeAdmin(admin.ModelAdmin):
    list_display = ('code', 'event', 'discount_type', 'discount_value', 'valid_from', 'valid_until', 'is_active')
    list_filter = ('discount_type', 'is_active', 'event')
    search_fields = ('code', 'event__title')
    readonly_fields = ('current_uses', 'created_at')
    list_editable = ('is_active',)

@admin.register(EventStaff)
class EventStaffAdmin(admin.ModelAdmin):
    list_display = ('user', 'event', 'role', 'assigned_at')
    list_filter = ('role', 'event')
    search_fields = ('user__email', 'event__title', 'notes')
    readonly_fields = ('assigned_at',)

@admin.register(TicketType)
class TicketTypeAdmin(admin.ModelAdmin):
    list_display = ('event', 'type_name', 'price', 'attendees_per_ticket')
    list_filter = ('type_name', 'event')
    search_fields = ('event__title', 'type_name')
    readonly_fields = ('total_attendees_capacity',)
    
    def total_attendees_capacity(self, obj):
        return obj.total_attendees_capacity
    total_attendees_capacity.short_description = 'Total Attendees Capacity'

@admin.register(PaymentTransaction)
class PaymentTransactionAdmin(admin.ModelAdmin):
    list_display = ('order_id', 'user', 'amount', 'status', 'payment_gateway', 'transaction_id', 'created_at', 'updated_at')
    list_filter = ('status', 'payment_gateway', 'created_at')
    search_fields = ('order_id', 'transaction_id', 'user__email')
    readonly_fields = ('created_at', 'updated_at')
    list_editable = ('status',)
    fieldsets = (
        ('Basic Information', {
            'fields': ('order_id', 'transaction_id', 'user', 'amount', 'status', 'payment_gateway')
        }),
        ('Response Data', {
            'fields': ('response_data',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )

# Only register User model if it hasn't been registered already
try:
    admin.site.register(User)
except admin.sites.AlreadyRegistered:
    pass

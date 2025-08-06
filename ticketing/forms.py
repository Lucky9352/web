from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from .models import User, Event, PromoCode, EventStaff, TicketType, EventSponsor
from .models import Ticket
from .google_drive_utils import is_valid_google_drive_url
import re

class OTPForm(forms.Form):
    otp = forms.CharField(
        max_length=6, 
        required=True, 
        widget=forms.TextInput(attrs={
            'class': 'shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline', 
            'placeholder': 'Enter 6-digit code'
        })
    )

class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'mobile_number', 'profile_picture']
        
class CustomUserCreationForm(UserCreationForm):
    first_name = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}))
    last_name = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}))
    mobile_number = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50', 'placeholder': 'e.g. +1234567890'}))
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}))
    password1 = forms.CharField(
        label="Create Password",
        help_text="Kindly create password.",
        widget=forms.PasswordInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}),
        required=True
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}),
        required=True
    )
    
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('email', 'first_name', 'last_name', 'mobile_number')
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:  # If editing an existing user
            self.fields['password1'].required = False
            self.fields['password2'].required = False
            self.fields['password1'].help_text = "Leave blank to keep current password"
            self.fields['password2'].help_text = "Leave blank to keep current password"

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        
        # If this is an existing user and both password fields are empty, skip password validation
        if self.instance.pk and not password1 and not password2:
            self._errors.pop('password1', None)
            self._errors.pop('password2', None)
            
        return cleaned_data
            
    def save(self, commit=True):
        user = super().save(commit=False)
        # If editing an existing user and both password fields are empty
        if self.instance.pk and not self.cleaned_data.get('password1') and not self.cleaned_data.get('password2'):
            # Retrieve the current password hash so it doesn't get overwritten
            user.password = User.objects.get(pk=self.instance.pk).password
        if commit:
            user.save()
        return user
        
class AdminUserCreationForm(UserCreationForm):
    first_name = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}))
    last_name = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}))
    mobile_number = forms.CharField(required=True, widget=forms.TextInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50', 'placeholder': 'e.g. +1234567890'}))
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}))
    role = forms.ChoiceField(choices=User.ROLE_CHOICES, required=True, widget=forms.Select(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}))
    profile_picture = forms.ImageField(required=False, widget=forms.FileInput(attrs={'class': 'mt-1 block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100'}))
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}),
        required=True
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50'}),
        required=True
    )
    
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('email', 'first_name', 'last_name', 'mobile_number', 'role', 'profile_picture')
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:  # If editing an existing user
            self.fields['password1'].required = False
            self.fields['password2'].required = False
            self.fields['password1'].help_text = "Leave blank to keep current password"
            self.fields['password2'].help_text = "Leave blank to keep current password"

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        
        # If this is an existing user and both password fields are empty, skip password validation
        if self.instance.pk and not password1 and not password2:
            self._errors.pop('password1', None)
            self._errors.pop('password2', None)
            
        return cleaned_data
            
    def save(self, commit=True):
        user = super().save(commit=False)
        # If editing an existing user and both password fields are empty
        if self.instance.pk and not self.cleaned_data.get('password1') and not self.cleaned_data.get('password2'):
            # Retrieve the current password hash so it doesn't get overwritten
            user.password = User.objects.get(pk=self.instance.pk).password
        if commit:
            user.save()
        return user
    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exclude(pk=self.instance.pk if self.instance.pk else None).exists():
            raise forms.ValidationError("This email address is already in use.")
        return email

class EventForm(forms.ModelForm):
    class Meta:
        model = Event
        fields = [
            'title', 'description', 'short_description', 
            'date', 'end_date', 'time', 'end_time',
            'venue', 'venue_address', 'venue_map_link',
            'capacity', 'event_type', 'venue_terms', 
            'event_terms', 'restrictions', 'banner_image_url', 
            'featured', 'registration_deadline', 'status'
        ]
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
            'end_date': forms.DateInput(attrs={'type': 'date'}),
            'time': forms.TimeInput(attrs={'type': 'time'}),
            'end_time': forms.TimeInput(attrs={'type': 'time'}),
            'registration_deadline': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'banner_image_url': forms.URLInput(attrs={
                'placeholder': 'https://drive.google.com/file/d/your-file-id/view',
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500'
            }),
        }
        help_texts = {
            'banner_image_url': 'Paste the Google Drive shareable link for the banner image. Make sure the link is set to "Anyone with the link can view".',
        }
    
    def clean_banner_image_url(self):
        """Validate Google Drive URL format"""
        url = self.cleaned_data.get('banner_image_url')
        if url:
            if not is_valid_google_drive_url(url):
                raise ValidationError(
                    'Please provide a valid Google Drive shareable link. '
                    'Example: https://drive.google.com/file/d/your-file-id/view'
                )
        return url

class PromoCodeForm(forms.ModelForm):
    class Meta:
        model = PromoCode
        fields = [
            'code', 'event', 'discount_type', 'discount_value',
            'valid_from', 'valid_until', 'max_uses', 'is_active'
        ]
        widgets = {
            'valid_from': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'valid_until': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
        }

class EventStaffForm(forms.ModelForm):
    class Meta:
        model = EventStaff
        fields = ['user', 'role', 'notes']
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Filter users to only show those with appropriate roles
        role = self.initial.get('role', None)
        if role == 'VOLUNTEER':
            self.fields['user'].queryset = User.objects.filter(role='VOLUNTEER')
        elif role == 'ORGANIZER':
            self.fields['user'].queryset = User.objects.filter(role='ORGANIZER')

class TicketTypeForm(forms.ModelForm):
    class Meta:
        model = TicketType
        fields = [
            'event', 'type_name', 'price', 'quantity', 'description', 'attendees_per_ticket'
        ]
        help_texts = {
            'quantity': 'Maximum number of tickets available (for informational purposes only)',
            'attendees_per_ticket': 'Number of attendees allowed per ticket (e.g., 2 for couple tickets)'
        }
        widgets = {
            'type_name': forms.TextInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500'}),
            'price': forms.NumberInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500', 'step': '0.01'}),
            'quantity': forms.NumberInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500'}),
            'description': forms.Textarea(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500', 'rows': 3}),
            'attendees_per_ticket': forms.NumberInput(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500', 'min': 1}),
            'event': forms.Select(attrs={'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make quantity field optional since it's not used for capacity enforcement
        self.fields['quantity'].required = False
        self.fields['quantity'].widget.attrs.update({'placeholder': 'Optional - for informational purposes only'})
    
    def clean_quantity(self):
        quantity = self.cleaned_data.get('quantity')
        # If quantity is None or empty, set it to 0
        if quantity is None or quantity == '':
            quantity = 0
        return quantity
        
    def save(self, commit=True):
        instance = super().save(commit=False)
        if commit:
            instance.save()
        return instance

class TicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ['event', 'ticket_type', 'customer', 'ticket_number', 'status', 'purchase_date']

class EventSponsorForm(forms.ModelForm):
    class Meta:
        model = EventSponsor
        fields = ['sponsor_name', 'logo_url', 'website_url', 'sponsor_type', 'order']
        widgets = {
            'sponsor_name': forms.TextInput(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500',
                'placeholder': 'Sponsor Name'
            }),
            'logo_url': forms.URLInput(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500',
                'placeholder': 'https://drive.google.com/file/d/your-file-id/view'
            }),
            'website_url': forms.URLInput(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500',
                'placeholder': 'https://sponsor-website.com (optional)'
            }),
            'sponsor_type': forms.TextInput(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500',
                'placeholder': 'e.g., Ticketing Partner, Gold Sponsor, Venue Partner'
            }),
            'order': forms.NumberInput(attrs={
                'class': 'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500',
                'placeholder': 'Display order (1, 2, 3...)'
            }),
        }
        help_texts = {
            'logo_url': 'Paste the Google Drive shareable link for the sponsor logo. Make sure the link is set to "Anyone with the link can view".',
            'sponsor_type': 'Specify the type of sponsorship (e.g., Ticketing Partner, Gold Sponsor, Venue Partner)',
            'order': 'Lower numbers appear first (e.g., 1 appears before 2)',
        }
    
    def clean_logo_url(self):
        """Validate Google Drive URL format for sponsor logo"""
        url = self.cleaned_data.get('logo_url')
        if url:
            if not is_valid_google_drive_url(url):
                raise ValidationError(
                    'Please provide a valid Google Drive shareable link for the logo. '
                    'Example: https://drive.google.com/file/d/your-file-id/view'
                )
        return url

# Formset for handling multiple sponsors
EventSponsorFormSet = forms.inlineformset_factory(
    Event, 
    EventSponsor, 
    form=EventSponsorForm,
    extra=1, 
    can_delete=True,
    min_num=0,
    validate_min=False
)

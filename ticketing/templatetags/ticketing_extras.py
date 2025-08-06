from django import template
from django.utils.safestring import mark_safe
from ..google_drive_utils import get_drive_image_url, extract_google_drive_id

register = template.Library()

@register.simple_tag
def google_drive_image(url_or_id, alt_text="", css_class="", use_thumbnail=False, size=800):
    """
    Template tag to display Google Drive images
    
    Usage:
        {% google_drive_image event.banner_image_url "Event Banner" "w-full h-48 object-cover" %}
        {% google_drive_image sponsor.logo_url "Sponsor Logo" "h-12" use_thumbnail=True size=200 %}
    """
    if not url_or_id:
        return ""
    
    image_url = get_drive_image_url(url_or_id, use_thumbnail, size)
    if not image_url:
        return ""
    
    return mark_safe(f'<img src="{image_url}" alt="{alt_text}" class="{css_class}">')

@register.filter
def google_drive_url(url_or_id):
    """
    Filter to convert Google Drive URL or ID to direct viewable URL
    
    Usage:
        {{ event.banner_image_url|google_drive_url }}
        {{ sponsor.logo_id|google_drive_url }}
    """
    return get_drive_image_url(url_or_id)

@register.filter
def google_drive_thumbnail(url_or_id, size=400):
    """
    Filter to get Google Drive thumbnail URL
    
    Usage:
        {{ event.banner_image_url|google_drive_thumbnail:800 }}
    """
    return get_drive_image_url(url_or_id, use_thumbnail=True, size=size)

@register.filter
def extract_drive_id(url):
    """
    Filter to extract Google Drive file ID from URL
    
    Usage:
        {{ google_drive_url|extract_drive_id }}
    """
    return extract_google_drive_id(url)

@register.filter
def multiply(value, arg):
    """Multiply value by arg."""
    try:
        return int(value) * int(arg)
    except (ValueError, TypeError):
        return 0

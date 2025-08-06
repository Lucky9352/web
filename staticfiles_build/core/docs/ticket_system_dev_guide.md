# Ticket Generation System - Developer Guide

## System Architecture

The ticket generation system follows these steps:

1. **Template Upload**:
   - Admins upload ticket templates when creating ticket types
   - Templates are stored in `media/ticket_templates/`

2. **Ticket Creation**:
   - When a ticket is purchased, a record is created in the database
   - A unique ticket number and secure token are generated

3. **On-Demand Generation**:
   - When a user requests their ticket, the system:
     - Loads the appropriate template based on ticket type
     - Generates a QR code with signed ticket data
     - Places the QR code at coordinates (670, 20) with size 200x200 pixels
     - Returns the combined image as a Base64-encoded string

4. **Ticket Validation**:
   - Volunteers scan the QR code using the provided interface
   - The system verifies the signature and ticket validity
   - If valid, the ticket status is updated to "USED"

## Key Files and Functions

### `api_ticket.py`
- `api_download_ticket(request, ticket_id)`: API endpoint for generating and downloading tickets
- `generate_ticket_image(ticket)`: Creates the ticket image with embedded QR code
- `create_signed_ticket_data(ticket)`: Generates signed data for the QR code

### `volunteer_views.py`
- `volunteer_scan_tickets(request)`: Renders the scanning interface
- `api_validate_ticket(request)`: API endpoint for validating scanned tickets

### Forms and Models
- `TicketTypeForm`: Includes fields for uploading ticket templates
- `TicketType` model: Stores the `image_template_url` field

## Data Flow

1. **Ticket Request**:
   ```
   User -> api_download_ticket -> generate_ticket_image -> create_signed_ticket_data -> User
   ```

2. **Ticket Validation**:
   ```
   Volunteer -> Scan QR -> api_validate_ticket -> Update Ticket Status
   ```

## Security Measures

1. **Signed Ticket Data**:
   - Each QR code contains the ticket data and a HMAC-SHA256 signature
   - The signature uses the ticket's unique secure token as the key

2. **On-Demand Generation**:
   - Ticket images are not stored in the database
   - Each ticket is generated fresh when requested

3. **Status Tracking**:
   - Tickets are marked as "USED" after validation
   - Attempted reuse is detected and prevented

## Customization Options

### QR Code Placement
To adjust the QR code placement, modify the `position` variable in the `generate_ticket_image` function:

```python
# Current implementation:
position = (670, 20)  # (x, y) coordinates for top-left corner

# If you need to adjust:
# For centered placement in a specific area:
# x = target_x + (target_width - qr_size) / 2
# y = target_y + (target_height - qr_size) / 2
```

### QR Code Size
To adjust the QR code size, modify the `qr_size` variable:

```python
# Current implementation:
qr_size = 200

# If you need to adjust:
# qr_size = different_value
```

### Template Management
Templates are stored in the media directory and referenced in the database. The path follows this pattern:

```
media/ticket_templates/event_{event_id}_{ticket_type_name}.jpg
```

## Testing Tools

We've provided a management command for testing:

```bash
python manage.py test_ticket_generation --ticket_id=ID --save
```

This generates a test ticket with a reference rectangle around the QR code placement area.

## Troubleshooting

1. **Missing Templates**: Check that templates exist at the expected path
2. **QR Code Placement**: Use the test command to visualize placement
3. **Scanning Issues**: Ensure QR codes are clear and sized appropriately

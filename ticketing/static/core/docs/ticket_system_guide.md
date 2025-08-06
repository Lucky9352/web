# Ticket Generation System Documentation

## Overview

The ticket generation system creates custom digital tickets with secure QR codes that can only be verified by the Tapnex scanning system. Tickets are generated on-demand and not stored in the database, ensuring security and reducing storage requirements.

## Key Components

### 1. Ticket Templates
- Templates are uploaded when creating or editing ticket types
- Templates are stored in the `media/ticket_templates/` directory
- File naming convention: `event_{event_id}_{ticket_type_name}.jpg`

### 2. QR Code Generation
- Each QR code contains a signed payload with the ticket ID and a secure token
- The payload is signed using HMAC-SHA256 for security
- The QR code is placed at coordinates (670, 20) with size 200x200 pixels

### 3. Ticket Generation
- Tickets are generated on-demand when requested by the user
- The system combines the ticket template with the QR code
- The final image is returned as a Base64-encoded string

### 4. QR Code Scanning
- Volunteers use the scanning interface to validate tickets
- The scanner verifies the signature and ticket validity
- Upon successful validation, the ticket status is updated to "USED"

## Testing the System

### Using the Management Command

We've provided a management command to test the ticket generation process:

```bash
# Basic test - finds a suitable ticket and generates an image (without saving)
python manage.py test_ticket_generation

# Test with a specific ticket ID and save the image
python manage.py test_ticket_generation --ticket_id=1 --save
```

The command will:
1. Find a suitable ticket (or use the specified ticket ID)
2. Generate the ticket image with QR code
3. Draw a reference rectangle around the QR code placement area
4. Save the image to `media/test_tickets/` if the `--save` flag is used

### Manual Testing

1. **Upload Templates**:
   - Go to the admin dashboard
   - Navigate to "Ticket Types" and create or edit a ticket type
   - Upload a template image for the ticket type

2. **Generate Tickets**:
   - Create a ticket for a user
   - Have the user navigate to "My Tickets"
   - Click on "Download Ticket" to generate the ticket with QR code

3. **Scan Tickets**:
   - Log in as a volunteer
   - Navigate to the ticket scanning interface
   - Scan the QR code on the ticket to validate it

## Troubleshooting

### QR Code Placement Issues
If the QR code is not properly placed:
- Use the test command with `--save` flag to generate a test ticket
- Check the template image dimensions
- Adjust the coordinates in the `generate_ticket_image` function if needed

### Scanning Problems
If scanning fails:
- Check that the QR code is clear and not too small
- Ensure the device has a good camera and sufficient lighting
- Verify that the volunteer has the proper permissions

### Template Issues
If templates are not loading:
- Check that the template path is correct in the database
- Ensure the template file exists in the media directory
- Verify that the file format is supported (JPG, PNG)

## Implementation Details

The QR code generation and placement has been optimized for the recommended coordinates:
- Top-left corner: (670, 20)
- Size: 200x200 pixels
- This places the QR code in the designated black rectangle area on the right side of the ticket templates

The ticket validation process uses HMAC signatures to ensure that only valid tickets can be scanned. Each ticket has a unique secure token that is used to sign the ticket data.

## Security Considerations

1. Tickets are generated on-demand and not stored in the database
2. QR codes contain signed data that can only be verified by the system
3. Each scan updates the ticket status to prevent reuse
4. The volunteer scanning system logs all validation attempts

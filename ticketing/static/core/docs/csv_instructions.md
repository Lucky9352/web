# CSV Upload Instructions for Event Creation

## File Format
The CSV file should be in standard CSV format with the following fields. Fields marked with * are required.

### Event Basic Information
- *`title`: Event title (max 200 characters)
- *`description`: Full event description
- *`event_type`: Type of event (e.g., Conference, Concert, Workshop, etc.)
- `short_description`: Brief description for listings (max 200 characters)
- `status`: Event status (DRAFT, PUBLISHED, CANCELLED) - defaults to DRAFT
- `featured`: Whether event is featured (True/False) - defaults to False

### Event Timing
- *`date`: Event start date in YYYY-MM-DD format (e.g., 2025-12-31)
- *`time`: Event start time in HH:MM format (24-hour) (e.g., 14:30)
- `end_date`: Event end date in YYYY-MM-DD format
- `end_time`: Event end time in HH:MM format
- `registration_deadline`: When registration closes, in YYYY-MM-DD HH:MM format

### Venue Information
- *`venue`: Name of the venue
- `venue_address`: Full address of the venue
- `venue_map_link`: Google Maps or other map service link
- *`capacity`: Total event capacity

### Terms and Conditions
- `venue_terms`: Venue specific terms and conditions
- `event_terms`: Event specific terms and conditions
- `restrictions`: Age restrictions or other limitations

### Ticket Types
You can define up to 4 ticket types. The first ticket type is mandatory.

#### Ticket Type 1 (Required)
- *`ticket_type_1`: Name of first ticket type
- *`ticket_price_1`: Price in decimal format (e.g., 99.99)
- *`ticket_quantity_1`: Number of tickets available
- `ticket_description_1`: Description of the ticket type
- `ticket_attendees_per_ticket_1`: Number of attendees allowed per ticket (defaults to 1)

#### Ticket Types 2-4 (Optional)
For each additional ticket type (2-4), you need to provide:
- `ticket_type_n`: Name of ticket type
- `ticket_price_n`: Price (required if type is provided)
- `ticket_quantity_n`: Quantity (required if type is provided)
- `ticket_description_n`: Description
- `ticket_attendees_per_ticket_n`: Number of attendees allowed per ticket (defaults to 1)

Where n is 2, 3, or 4.

## Example Row
```csv
title,description,event_type,short_description,date,time,venue,capacity,ticket_type_1,ticket_price_1,ticket_quantity_1,ticket_attendees_per_ticket_1
"Summer Concert","Amazing summer concert with top artists","CONCERT","Summer festival with great music","2025-08-15","19:00","Central Park","500","General Admission",50.00,400,1
```

## Complete Example
The sample CSV you can download includes a complete example with all available fields populated.

## Tips
1. At least one ticket type is required
2. If you provide a ticket type, you must also provide its price and quantity
3. Dates must be in YYYY-MM-DD format
4. Times must be in 24-hour HH:MM format
5. Registration deadline must be in YYYY-MM-DD HH:MM format (e.g., 2025-08-10 23:59)
6. Prices should use decimal point (not comma) and include cents (e.g., 50.00)
7. Text fields can contain commas if the field is enclosed in double quotes
8. Empty optional fields can be left blank

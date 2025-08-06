# Event Information CSV Guide

## Overview
This document provides detailed instructions for filling out the CSV (Comma-Separated Values) file to create events in our ticketing system. Please provide complete information following the format below to ensure your event is created correctly.

## How to Fill the CSV File
1. Open the provided CSV template in Excel, Google Sheets, or any spreadsheet software
2. Fill in all required fields and as many optional fields as applicable
3. Save the file as CSV format (.csv)
4. Upload the completed file through the event creation interface

## Event Details - CSV Column Specifications

### Required Event Information
These fields must be completed for your event to be created:

| Column Name | Description | Format/Example |
|-------------|-------------|----------------|
| `title` | Official name of your event | "Annual Music Festival 2025" |
| `description` | Detailed description of the event | "Join us for a weekend of live music featuring..." |
| `date` | Event start date | YYYY-MM-DD (e.g., 2025-12-31) |
| `time` | Event start time | HH:MM in 24-hour format (e.g., 18:30) |
| `venue` | Name of the venue | "City Convention Center" |

### Optional Event Information
The following fields provide additional event details:

| Column Name | Description | Format/Example |
|-------------|-------------|----------------|
| `short_description` | Brief summary for listings | "Two-day music festival with 20+ bands" |
| `end_date` | Event end date | YYYY-MM-DD (e.g., 2025-12-31) |
| `end_time` | Event end time | HH:MM in 24-hour format (e.g., 22:00) |
| `venue_address` | Complete address of venue | "123 Main Street, Cityville, ST 12345" |
| `venue_map_link` | URL to map location | "https://maps.google.com/?q=..." |
| `capacity` | Total event capacity | Numeric value (e.g., 1000) |
| `registration_deadline` | Last date to register | YYYY-MM-DD HH:MM (e.g., 2025-12-30 23:59) |
| `venue_terms` | Venue-specific rules | "No outside food or beverages allowed..." |
| `event_terms` | Event-specific terms | "By attending this event, you agree to..." |
| `restrictions` | Age/accessibility info | "18+ only. Venue is wheelchair accessible." |
| `status` | Publishing status | "DRAFT", "PUBLISHED", or "CANCELLED" |
| `featured` | Highlight on homepage | "True" or "False" |
| `banner_image` | URL to event banner | "https://example.com/image.jpg" or leave blank |

### Ticket Types Information
You can define up to 4 different ticket types in the CSV. For each type #, provide:

| Column Name | Description | Format/Example |
|-------------|-------------|----------------|
| `ticket_type_#` | Name of ticket category | "General Admission", "VIP", etc. |
| `ticket_price_#` | Cost per ticket | Decimal value (e.g., 99.99) |
| `ticket_quantity_#` | Number available | Integer value (e.g., 500) |
| `ticket_description_#` | Details about this ticket | "Includes access to all stages and one drink token" |
| `ticket_attendees_per_ticket_#` | People per ticket | Integer (e.g., 1 for individual, 2 for couples) |

Where # is 1, 2, 3, or 4. At least one complete ticket type is required.

## Complete CSV Example
Here's what your completed CSV might look like:

```
title,description,date,time,venue,short_description,end_date,end_time,venue_address,venue_map_link,capacity,registration_deadline,venue_terms,event_terms,restrictions,status,featured,ticket_type_1,ticket_price_1,ticket_quantity_1,ticket_description_1,ticket_attendees_per_ticket_1,ticket_type_2,ticket_price_2,ticket_quantity_2,ticket_description_2,ticket_attendees_per_ticket_2,ticket_type_3,ticket_price_3,ticket_quantity_3,ticket_description_3,ticket_attendees_per_ticket_3,ticket_type_4,ticket_price_4,ticket_quantity_4,ticket_description_4,ticket_attendees_per_ticket_4
Summer Music Festival 2025,Join us for our annual summer music festival featuring top artists from around the world. This year's lineup includes multiple stages and genres including rock, pop, EDM, and jazz.,2025-07-15,14:00,Central Park,Two-day music festival with 20+ bands,2025-07-16,23:00,"Central Park, New York, NY 10022",https://goo.gl/maps/example,5000,2025-07-10 23:59,"No outside food or beverages. No smoking in designated areas. All bags subject to search.","By purchasing this ticket you agree to follow venue rules and event policies. No refunds except in case of event cancellation.","18+ event. ID required. Wheelchair accessible.",PUBLISHED,True,General Admission,50.00,3000,"Basic entry to all stages",1,VIP Pass,150.00,500,"Premium viewing areas, backstage access, and complimentary drinks",1,Group Package,175.00,100,"Admission for 4 people with one reserved table",4,Early Bird,35.00,1000,"Limited discounted general admission tickets",1
```

## Important Notes for CSV Preparation

1. **No Text Limitations**: Include as much detail as needed in description fields. There are no character limits for text fields such as event descriptions, terms, etc.

2. **Date and Time Format**: Be precise with date (YYYY-MM-DD) and time (24-hour HH:MM) formats. Incorrect formats will cause processing errors.

3. **CSV Formatting**: 
   - Ensure commas within text fields are properly handled (most spreadsheet programs do this automatically when saving as CSV)
   - If your text contains commas, ensure the text is enclosed in double quotes when saving as CSV
   - Do not add extra spaces before or after commas

4. **File Processing**:
   - Currently, only the first row (after headers) will be processed as an event
   - For multiple events, please prepare and submit separate CSV files
   - The system will attempt to process files with minor issues but may return error messages

5. **Multi-Day Events**: For events spanning multiple days, provide both start and end dates/times.

6. **Pricing**: Enter all prices as decimal numbers without currency symbols (e.g., 25.00, not $25).

7. **Special Characters**: Most special characters are supported in text fields, but avoid using HTML tags or script elements.

8. **Image References**: If referencing image URLs, ensure they are publicly accessible.

## File Submission

After completing your CSV file:
1. Save it with a descriptive name (e.g., "SummerFestival2025.csv")
2. Upload it using the CSV upload option on the event creation page
3. Review any system messages after upload
4. Check the created event in draft mode before publishing

## Questions or Assistance
If you encounter difficulties filling out or uploading your CSV file, please contact our support team at support@example.com or call (555) 123-4567.

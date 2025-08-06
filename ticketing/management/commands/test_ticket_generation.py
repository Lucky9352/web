from django.core.management.base import BaseCommand
from django.conf import settings
from ticketing.models import Ticket, TicketType
from ticketing.api_ticket import generate_ticket_image
import os
from PIL import Image, ImageDraw

class Command(BaseCommand):
    help = 'Test ticket generation with QR codes'

    def add_arguments(self, parser):
        parser.add_argument('--ticket_id', type=int, help='ID of the ticket to test')
        parser.add_argument('--save', action='store_true', help='Save the generated ticket to a file')

    def handle(self, *args, **options):
        ticket_id = options.get('ticket_id')
        save_file = options.get('save', False)

        try:
            # Get a ticket to test
            if ticket_id:
                ticket = Ticket.objects.get(id=ticket_id)
                self.stdout.write(f"Using specified ticket: {ticket}")
            else:
                # Get the first available ticket with a valid ticket type and template
                tickets = Ticket.objects.filter(
                    ticket_type__isnull=False,
                    ticket_type__image_template_url__isnull=False
                )
                
                if not tickets.exists():
                    self.stdout.write(self.style.ERROR("No suitable tickets found with ticket types and templates"))
                    return
                
                ticket = tickets.first()
                self.stdout.write(f"Using first available ticket: {ticket}")

            # Generate the ticket image
            self.stdout.write("Generating ticket image...")
            ticket_image = generate_ticket_image(ticket)
            
            # Draw a reference rectangle around the QR code placement area
            draw = ImageDraw.Draw(ticket_image)
            # Draw rectangle from (670, 20) to (870, 220) with a red outline
            draw.rectangle([(670, 20), (870, 220)], outline="red", width=2)
            
            # Save the image if requested
            if save_file:
                output_dir = os.path.join(settings.MEDIA_ROOT, 'test_tickets')
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, f"test_ticket_{ticket.id}.png")
                ticket_image.save(output_path)
                self.stdout.write(self.style.SUCCESS(f"Saved ticket image to: {output_path}"))
                
                # Show the full path for easier access
                full_path = os.path.abspath(output_path)
                self.stdout.write(f"Full path: {full_path}")
            else:
                self.stdout.write(self.style.SUCCESS("Ticket generated successfully but not saved (use --save to save)"))
                
            # Print dimensions information
            self.stdout.write(f"Ticket image dimensions: {ticket_image.width}x{ticket_image.height}")
            self.stdout.write(f"QR code placement area: (670, 20) to (870, 220)")
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error: {str(e)}"))

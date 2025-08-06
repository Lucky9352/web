import random
import string
from django.core.management.base import BaseCommand
from ticketing.models import Ticket

class Command(BaseCommand):
    help = 'Regenerates shorter secure tokens for tickets'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            dest='dry_run',
            help='Show how many tickets would be updated but don\'t actually modify them',
        )
        
        parser.add_argument(
            '--length',
            type=int,
            default=6,
            help='Length of the token to generate (default: 6)',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        token_length = options['length']
        
        # Get all tickets that need new tokens or those with tokens longer than our new format
        tickets = Ticket.objects.filter(status__in=['AVAILABLE', 'RESERVED', 'SOLD', 'VALID'])
        
        if dry_run:
            self.stdout.write(f"Would update {tickets.count()} tickets")
            return
        
        count = 0
        for ticket in tickets:
            # Generate a new short unique token
            unique_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=token_length))
            ticket.unique_secure_token = unique_id
            ticket.save(update_fields=['unique_secure_token'])
            count += 1
            
            if count % 100 == 0:  # Progress indicator for large datasets
                self.stdout.write(f"Updated {count} tickets...")
        
        self.stdout.write(self.style.SUCCESS(f'Successfully updated {count} tickets with new short tokens'))

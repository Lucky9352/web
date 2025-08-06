"""
Management command to test Google Drive URL functionality
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from ticketing.google_drive_utils import (
    extract_google_drive_id,
    get_google_drive_direct_url,
    is_valid_google_drive_url,
    validate_and_extract_drive_info
)


class Command(BaseCommand):
    help = 'Test Google Drive URL functionality with various URL formats'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--url',
            type=str,
            help='Test a specific Google Drive URL',
        )
        parser.add_argument(
            '--test-all',
            action='store_true',
            help='Run tests with sample URLs',
        )
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('=== Google Drive URL Testing Tool ===\n')
        )
        
        if options['url']:
            self.test_single_url(options['url'])
        elif options['test_all']:
            self.test_sample_urls()
        else:
            self.show_usage()
    
    def test_single_url(self, url):
        """Test a single URL"""
        self.stdout.write(f"Testing URL: {url}\n")
        
        # Validate and extract information
        result = validate_and_extract_drive_info(url)
        
        if result['is_valid']:
            self.stdout.write(self.style.SUCCESS("✓ Valid Google Drive URL"))
            self.stdout.write(f"File ID: {result['file_id']}")
            self.stdout.write(f"Direct URL: {result['direct_url']}")
            self.stdout.write(f"Thumbnail URL: {result['thumbnail_url']}")
            self.stdout.write(f"Preview URL: {result['preview_url']}")
        else:
            self.stdout.write(self.style.ERROR(f"✗ Invalid URL: {result['error_message']}"))
    
    def test_sample_urls(self):
        """Test with sample URLs"""
        sample_urls = [
            'https://drive.google.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/view',
            'https://drive.google.com/open?id=1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms',
            'https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit',
            'https://drive.google.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit',
            'invalid-url',
            '',
        ]
        
        for i, url in enumerate(sample_urls, 1):
            self.stdout.write(f"\n--- Test {i} ---")
            if url:
                self.test_single_url(url)
            else:
                self.stdout.write("Testing empty URL:")
                result = validate_and_extract_drive_info(url)
                self.stdout.write(self.style.WARNING(f"✗ {result['error_message']}"))
    
    def show_usage(self):
        """Show usage examples"""
        self.stdout.write("Usage examples:")
        self.stdout.write("  python manage.py test_google_drive --test-all")
        self.stdout.write("  python manage.py test_google_drive --url 'https://drive.google.com/file/d/YOUR_FILE_ID/view'")
        self.stdout.write("\nSupported Google Drive URL formats:")
        self.stdout.write("  • https://drive.google.com/file/d/FILE_ID/view")
        self.stdout.write("  • https://drive.google.com/open?id=FILE_ID")
        self.stdout.write("  • https://docs.google.com/document/d/FILE_ID/edit")
        self.stdout.write("  • https://drive.google.com/file/d/FILE_ID/edit")
        self.stdout.write("\nHow to get a Google Drive shareable link:")
        self.stdout.write("  1. Right-click the file in Google Drive")
        self.stdout.write("  2. Select 'Share'")
        self.stdout.write("  3. Change permissions to 'Anyone with the link can view'")
        self.stdout.write("  4. Copy the link and paste it in the form")

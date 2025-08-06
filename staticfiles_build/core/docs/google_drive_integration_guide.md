# Google Drive Image Integration Guide

This ticketing system uses Google Drive to host event banners and sponsor logos. This approach provides several benefits:

- **Reliable hosting**: Google Drive provides stable, fast image hosting
- **Easy management**: Images can be managed directly from Google Drive
- **Cost-effective**: No additional storage costs for the application
- **Scalable**: No server storage limitations

## Setting Up Google Drive Images

### Step 1: Upload Your Image to Google Drive
1. Go to [Google Drive](https://drive.google.com)
2. Click "+ New" → "File upload"
3. Select your image file (JPG, PNG, etc.)
4. Wait for the upload to complete

### Step 2: Make the Image Publicly Accessible
1. Right-click on the uploaded image
2. Select "Share" from the context menu
3. Click "Change to anyone with the link"
4. Ensure the permission is set to "Viewer"
5. Click "Copy link"

### Step 3: Use the Link in the Form
1. Paste the copied Google Drive link into the appropriate URL field:
   - **Event Banner**: Use the "Banner Image URL" field in the event form
   - **Sponsor Logo**: Use the "Logo URL (Google Drive)" field in the sponsor section

## Supported URL Formats

The system automatically detects and processes these Google Drive URL formats:

```
https://drive.google.com/file/d/FILE_ID/view
https://drive.google.com/open?id=FILE_ID
https://docs.google.com/document/d/FILE_ID/edit
https://drive.google.com/file/d/FILE_ID/edit
```

## Testing Your URLs

The event creation form includes "Test URL" buttons that help you verify:
- ✅ **Valid URL**: The link is correctly formatted and accessible
- ⚠️ **URL works but may not be publicly accessible**: The URL format is correct, but sharing permissions might need adjustment
- ❌ **Invalid URL format**: The URL is not a valid Google Drive link

## Managing Multiple Sponsors

### Adding Sponsors
1. Fill in the first sponsor form that appears by default
2. Click the "Add Another Sponsor" button to add more sponsors
3. Each sponsor needs:
   - **Sponsor Name**: The display name
   - **Logo URL**: Google Drive link to the sponsor's logo
   - **Website URL**: (Optional) The sponsor's website
   - **Sponsor Type**: Type of sponsorship (e.g., Ticketing Partner, Gold Sponsor, Venue Partner)
   - **Display Order**: Lower numbers appear first (1, 2, 3...)

### Removing Sponsors
- Click the red trash icon next to any sponsor (except the first one)
- For existing sponsors, they'll be marked for deletion but not removed until you save
- For new sponsors, they're immediately removed from the form

## Best Practices

### Image Specifications
- **Event Banners**: Recommended size 1200x600px or similar 2:1 ratio
- **Sponsor Logos**: Recommended size 400x200px or maintain brand proportions
- **Format**: JPG or PNG
- **File Size**: Keep under 5MB for faster loading

### Naming Convention
Use descriptive filenames in Google Drive:
```
event-banner-tech-conference-2025.jpg
sponsor-logo-company-name.png
```

### Folder Organization
Create organized folders in Google Drive:
```
📁 Ticketing System Images
  📁 Event Banners
    📁 2025
      📄 tech-conference-banner.jpg
      📄 music-festival-banner.jpg
  📁 Sponsor Logos
    📁 Tech Conference 2025
      📄 microsoft-logo.png
      📄 google-logo.png
```

## Troubleshooting

### Common Issues

**"Invalid Google Drive URL format"**
- Ensure you're using a Google Drive link, not a link to another service
- Check that the URL contains either `/d/` or `id=` parameter

**"URL works but may not be publicly accessible"**
- Go back to Google Drive and check sharing permissions
- Make sure it's set to "Anyone with the link can view"
- Avoid using "Restricted" sharing

**Image not displaying on the website**
- Wait a few minutes for Google's CDN to update
- Clear your browser cache
- Try the "Test URL" button in the form

**File ID extraction fails**
- Make sure you're copying the full URL from Google Drive
- Don't modify the URL after copying it
- Try generating a new shareable link

### Getting Help

If you encounter issues:

1. **Test with the management command**:
   ```bash
   python manage.py test_google_drive --url "your-google-drive-url"
   ```

2. **Run comprehensive tests**:
   ```bash
   python manage.py test_google_drive --test-all
   ```

3. **Check the application logs** for any error messages

## Security Considerations

- **Public Access**: Images shared via Google Drive are publicly accessible to anyone with the link
- **Link Sharing**: Keep track of your shareable links
- **Content Policy**: Ensure all images comply with Google Drive's terms of service
- **Backup**: Keep local copies of important images

## API Usage

For developers integrating with the system:

### Available Utility Functions

```python
from ticketing.google_drive_utils import (
    extract_google_drive_id,
    get_google_drive_direct_url,
    is_valid_google_drive_url,
    validate_and_extract_drive_info
)

# Extract file ID
file_id = extract_google_drive_id("https://drive.google.com/file/d/ABC123/view")

# Get direct URL
direct_url = get_google_drive_direct_url(file_id)

# Validate URL
is_valid = is_valid_google_drive_url("https://drive.google.com/file/d/ABC123/view")

# Get complete information
info = validate_and_extract_drive_info("https://drive.google.com/file/d/ABC123/view")
```

### Template Tags

```django
{% load ticketing_extras %}

<!-- Display Google Drive image -->
{% google_drive_image event.banner_image_url "Event Banner" "w-full h-48 object-cover" %}

<!-- Get direct URL -->
<img src="{{ event.banner_image_url|google_drive_url }}" alt="Banner">

<!-- Get thumbnail URL -->
<img src="{{ sponsor.logo_url|google_drive_thumbnail:400 }}" alt="Logo">
```

This system provides a robust, scalable solution for managing event images while maintaining ease of use for event organizers.

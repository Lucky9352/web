/**
 * Ticket Download Functions
 * 
 * This file contains functions for ticket download functionality.
 */

// Function to download ticket via API
async function downloadTicket(ticketId) {
    // Show the modal with loading state
    document.getElementById('ticket-modal').classList.remove('hidden');
    document.getElementById('ticket-loading').classList.remove('hidden');
    document.getElementById('ticket-image').src = '';
    
    try {
        // Make API request to generate ticket image
        const response = await fetch(`/api/ticket/download/${ticketId}/`);
        const data = await response.json();
        
        if (data.success) {
            const imgSrc = `data:image/png;base64,${data.ticket_image}`;
            
            // Update the ticket image
            const ticketImg = document.getElementById('ticket-image');
            ticketImg.src = imgSrc;
            
            // Update download link
            const downloadLink = document.getElementById('download-link');
            downloadLink.href = imgSrc;
            downloadLink.download = `ticket_${data.ticket_number}.png`;
            
            // Hide loading indicator
            document.getElementById('ticket-loading').classList.add('hidden');
        } else {
            alert('Error generating ticket: ' + data.message);
            closeTicketModal();
        }
    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while generating your ticket.');
        closeTicketModal();
    }
}

// Function to close the ticket modal
function closeTicketModal() {
    document.getElementById('ticket-modal').classList.add('hidden');
}

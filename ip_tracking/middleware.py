import logging
from django.utils import timezone


def get_client_ip(request):
    """Extract the client's IP address from the request."""
    # Handle X-Forwarded-For header for proxies
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class IPTrackingMiddleware:
    """Middleware to track IP addresses and paths."""
    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger('ip_tracking')

    def get_client_ip(self, request):
        """Extract the client's IP address from the request."""
        return get_client_ip(request)

    def __call__(self, request):
        """Process the request to log IP address and path."""
        ip_address = self.get_client_ip(request)
        path = request.get_full_path()
        timestamp = timezone.now()
        self.logger.info(f"IP: {ip_address}, Path: {path}, Timestamp: {timestamp}")
        # Process the request
        response = self.get_response(request)
        return response

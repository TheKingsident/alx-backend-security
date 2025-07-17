import logging
import requests
from django.utils import timezone
from django.http import HttpResponseForbidden, HttpResponse
from django.core.cache import cache
from django_ratelimit.decorators import ratelimit
from django_ratelimit import ALL
from django_ratelimit.exceptions import Ratelimited
from .models import BlockedIP, RequestLog


def get_client_ip(request):
    """Extract the client's IP address from the request."""
    # Handle X-Forwarded-For header for proxies
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_geolocation(ip_address):
    """Get geolocation data for an IP address with 24-hour caching."""
    # Create cache key
    cache_key = f"geolocation_{ip_address}"
    
    # Try to get from cache first
    cached_location = cache.get(cache_key)
    if cached_location:
        return cached_location
    
    # Skip geolocation for private/local IPs
    if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
        location_data = {'country': 'Local', 'city': 'Local'}
        cache.set(cache_key, location_data, 60 * 60 * 24)
        return location_data
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                location_data = {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown')
                }
            else:
                location_data = {'country': 'Unknown', 'city': 'Unknown'}
        else:
            location_data = {'country': 'Unknown', 'city': 'Unknown'}
        
        # Cache the result for 24 hours (86400 seconds)
        cache.set(cache_key, location_data, 60 * 60 * 24)
        return location_data
        
    except requests.RequestException:
        # Fallback if API request fails
        location_data = {'country': 'Unknown', 'city': 'Unknown'}
        # Cache failed lookups for shorter time (1 hour)
        cache.set(cache_key, location_data, 60 * 60)
        return location_data

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
        
        # Get geolocation data
        location_data = get_geolocation(ip_address)
        
        # Log to console/file
        self.logger.info(
            f"IP: {ip_address}, Path: {path}, Timestamp: {timestamp}, "
            f"Country: {location_data['country']}, City: {location_data['city']}"
        )
        
        # Save to database
        try:
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
                country=location_data['country'],
                city=location_data['city']
            )
        except Exception as e:
            self.logger.error(f"Failed to save request log: {e}")

        response = self.get_response(request)
        return response

class BlockedIPMiddleware:
    """Middleware to block requests from specific IP addresses."""
    def __init__(self, get_response):
        self.get_response = get_response

    def get_client_ip(self, request):
        """Extract the client's IP address from the request."""
        return get_client_ip(request)

    def __call__(self, request):
        """Check if the request's IP is blocked."""
        ip_address = self.get_client_ip(request)
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access denied")
        response = self.get_response(request)
        return response


class RateLimitMiddleware:
    """Middleware to implement rate limiting based on user authentication status."""
    
    def __init__(self, get_response):
        self.get_response = get_response

    def get_client_ip(self, request):
        """Extract the client's IP address from the request."""
        return get_client_ip(request)

    def __call__(self, request):
        """Apply rate limiting based on authentication status."""
        
        # Check if user is authenticated
        is_authenticated = hasattr(request, 'user') and request.user.is_authenticated
        
        try:
            if is_authenticated:
                # 10 requests per minute for authenticated users
                self._check_rate_limit_authenticated(request)
            else:
                # 5 requests per minute for anonymous users
                self._check_rate_limit_anonymous(request)
                
        except Ratelimited:
            # Return 429 Too Many Requests
            return HttpResponse(
                "Rate limit exceeded. Please try again later.",
                status=429,
                content_type="text/plain"
            )
        
        response = self.get_response(request)
        return response
    
    def _check_rate_limit_authenticated(self, request):
        """Check rate limit for authenticated users (10/minute)."""
        from django_ratelimit.core import is_ratelimited
        
        # Use user ID as the key for authenticated users
        key = f"user_{request.user.id}"
        
        if is_ratelimited(
            request=request,
            group=key,
            fn=None,
            key='user',
            rate='10/m',
            method=ALL,
            increment=True
        ):
            raise Ratelimited()
    
    def _check_rate_limit_anonymous(self, request):
        """Check rate limit for anonymous users (5/minute)."""
        from django_ratelimit.core import is_ratelimited
        
        # Use IP address as the key for anonymous users
        ip_address = self.get_client_ip(request)
        
        if is_ratelimited(
            request=request,
            group=f"anon_{ip_address}",
            fn=None,
            key='ip',
            rate='5/m',
            method=ALL,
            increment=True
        ):
            raise Ratelimited()
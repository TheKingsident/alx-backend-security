from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.conf import settings


def get_client_ip(request):
    """Get client IP address."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@ratelimit(key='ip', rate=settings.RATE_LIMIT_SETTINGS.get('LOGIN_IP_BASED', '3/m'), 
           method='POST', block=True)
def login_view(request):
    """
    Login view with rate limiting.
    - 3 login attempts per minute per IP address
    - Blocks excessive login attempts to prevent brute force attacks
    """
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Login successful!')
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Please provide both username and password.')
    
    return render(request, 'login.html')


def ratelimited_error(request, exception):
    """
    Custom view to handle rate limiting errors.
    This view is called when rate limiting is triggered.
    """
    return HttpResponse(
        "Too many login attempts. Please try again later.",
        status=429,
        content_type="text/plain"
    )


def dashboard_view(request):
    """Simple dashboard view (requires login)."""
    if not request.user.is_authenticated:
        return redirect('login')
    
    return render(request, 'dashboard.html', {
        'user': request.user
    })

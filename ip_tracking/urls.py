from django.urls import path
from . import views

app_name = 'ip_tracking'

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
]

# Set custom rate limit error handler
handler429 = 'ip_tracking.views.ratelimited_error'

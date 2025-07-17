from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
import logging
from .models import RequestLog, SuspiciousIP, BlockedIP

logger = logging.getLogger('ip_tracking')


@shared_task
def monitor_suspicious_activity():
    """
    Celery task to monitor and flag suspicious IP activity.
    Runs hourly to check for:
    1. IPs exceeding 100 requests/hour
    2. IPs accessing sensitive paths (admin, login, etc.)
    """
    logger.info("Starting suspicious activity monitoring task")
    
    # Define the time window (last hour)
    one_hour_ago = timezone.now() - timedelta(hours=1)
    
    # Define sensitive paths to monitor
    sensitive_paths = [
        '/admin',
        '/login',
    ]
    
    # Check for high request volume (>100 requests/hour)
    high_volume_ips = check_high_volume_requests(one_hour_ago)
    
    # Check for sensitive path access
    sensitive_path_ips = check_sensitive_path_access(one_hour_ago, sensitive_paths)
    
    # Check for rapid successive requests (possible bot behavior)
    rapid_request_ips = check_rapid_requests(one_hour_ago)
    
    total_flagged = len(high_volume_ips) + len(sensitive_path_ips) + len(rapid_request_ips)
    
    logger.info(f"Suspicious activity monitoring completed. Flagged {total_flagged} suspicious IPs")
    
    return {
        'high_volume_ips': len(high_volume_ips),
        'sensitive_path_ips': len(sensitive_path_ips),
        'rapid_request_ips': len(rapid_request_ips),
        'total_flagged': total_flagged,
        'checked_period': f"{one_hour_ago} to {timezone.now()}"
    }


def check_high_volume_requests(since_time):
    """Check for IPs with more than 100 requests in the last hour."""
    high_volume_ips = RequestLog.objects.filter(
        timestamp__gte=since_time
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(
        request_count__gt=100
    )
    
    flagged_ips = []
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Skip if already flagged recently (within last 6 hours)
        if not recently_flagged(ip_address, hours=6):
            reason = f"High request volume: {request_count} requests in the last hour (threshold: 100)"
            
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=reason,
                request_count=request_count
            )
            
            flagged_ips.append(ip_address)
            logger.warning(f"Flagged IP {ip_address} for high volume: {request_count} requests/hour")
    
    return flagged_ips


def check_sensitive_path_access(since_time, sensitive_paths):
    """Check for IPs accessing sensitive paths."""
    # Build Q objects for sensitive path filtering
    path_filters = Q()
    for path in sensitive_paths:
        path_filters |= Q(path__icontains=path)
    
    sensitive_access_ips = RequestLog.objects.filter(
        timestamp__gte=since_time
    ).filter(path_filters).values('ip_address').annotate(
        request_count=Count('id'),
        paths_accessed=Count('path', distinct=True)
    )
    
    flagged_ips = []
    
    for ip_data in sensitive_access_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        paths_count = ip_data['paths_accessed']
        
        # Skip if already flagged recently
        if not recently_flagged(ip_address, hours=6):
            # Get specific paths accessed
            accessed_paths = RequestLog.objects.filter(
                ip_address=ip_address,
                timestamp__gte=since_time
            ).filter(path_filters).values_list('path', flat=True).distinct()
            
            reason = (
                f"Sensitive path access: {request_count} requests to {paths_count} "
                f"sensitive paths. Accessed: {', '.join(list(accessed_paths)[:5])}"
                f"{'...' if len(accessed_paths) > 5 else ''}"
            )
            
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=reason,
                request_count=request_count
            )
            
            flagged_ips.append(ip_address)
            logger.warning(f"Flagged IP {ip_address} for sensitive path access: {list(accessed_paths)}")
    
    return flagged_ips


def check_rapid_requests(since_time):
    """Check for IPs making rapid successive requests (possible bot behavior)."""
    # Look for IPs with more than 50 requests in any 5-minute window
    five_minutes_intervals = []
    current_time = timezone.now()
    
    # Check 12 five-minute intervals in the last hour
    for i in range(12):
        interval_start = current_time - timedelta(minutes=5 * (i + 1))
        interval_end = current_time - timedelta(minutes=5 * i)
        five_minutes_intervals.append((interval_start, interval_end))
    
    flagged_ips = []
    
    for interval_start, interval_end in five_minutes_intervals:
        rapid_ips = RequestLog.objects.filter(
            timestamp__gte=interval_start,
            timestamp__lt=interval_end
        ).values('ip_address').annotate(
            request_count=Count('id')
        ).filter(
            request_count__gt=50  # More than 50 requests in 5 minutes
        )
        
        for ip_data in rapid_ips:
            ip_address = ip_data['ip_address']
            request_count = ip_data['request_count']
            
            # Skip if already flagged recently or already in this batch
            if not recently_flagged(ip_address, hours=6) and ip_address not in flagged_ips:
                reason = (
                    f"Rapid requests: {request_count} requests in 5-minute window "
                    f"({interval_start.strftime('%H:%M')} - {interval_end.strftime('%H:%M')})"
                )
                
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=reason,
                    request_count=request_count
                )
                
                flagged_ips.append(ip_address)
                logger.warning(f"Flagged IP {ip_address} for rapid requests: {request_count} in 5 minutes")
    
    return flagged_ips


def recently_flagged(ip_address, hours=6):
    """Check if an IP was flagged recently to avoid duplicate alerts."""
    recent_threshold = timezone.now() - timedelta(hours=hours)
    return SuspiciousIP.objects.filter(
        ip_address=ip_address,
        detected_at__gte=recent_threshold,
        is_resolved=False
    ).exists()


@shared_task
def auto_block_highly_suspicious_ips():
    """
    Automatically block IPs that are flagged multiple times or show extreme behavior.
    This is a separate task that can be run less frequently.
    """
    logger.info("Starting auto-block task for highly suspicious IPs")
    
    # Define criteria for auto-blocking
    twenty_four_hours_ago = timezone.now() - timedelta(hours=24)
    
    # Find IPs flagged multiple times in 24 hours
    repeat_offenders = SuspiciousIP.objects.filter(
        detected_at__gte=twenty_four_hours_ago,
        is_resolved=False
    ).values('ip_address').annotate(
        flag_count=Count('id')
    ).filter(
        flag_count__gte=3  # 3 or more flags in 24 hours
    )
    
    blocked_count = 0
    
    for ip_data in repeat_offenders:
        ip_address = ip_data['ip_address']
        flag_count = ip_data['flag_count']
        
        # Check if not already blocked
        if not BlockedIP.objects.filter(ip_address=ip_address).exists():
            BlockedIP.objects.create(ip_address=ip_address)
            
            # Mark related suspicious IPs as resolved
            SuspiciousIP.objects.filter(
                ip_address=ip_address,
                is_resolved=False
            ).update(is_resolved=True)
            
            blocked_count += 1
            logger.critical(f"Auto-blocked IP {ip_address} after {flag_count} suspicious activity flags")
    
    logger.info(f"Auto-block task completed. Blocked {blocked_count} IPs")
    
    return {
        'blocked_count': blocked_count,
        'checked_period': f"{twenty_four_hours_ago} to {timezone.now()}"
    }


@shared_task
def cleanup_old_suspicious_records():
    """Clean up old suspicious IP records to prevent database bloat."""
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    # Delete resolved suspicious IP records older than 30 days
    deleted_count = SuspiciousIP.objects.filter(
        detected_at__lt=thirty_days_ago,
        is_resolved=True
    ).delete()[0]
    
    logger.info(f"Cleaned up {deleted_count} old suspicious IP records")
    
    return {'cleaned_records': deleted_count}

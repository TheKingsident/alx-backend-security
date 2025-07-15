from django.core.management.base import BaseCommand, CommandError
from django.core.exceptions import ValidationError
from ip_tracking.models import BlockedIP
import ipaddress


class Command(BaseCommand):
    """Management command to block IP addresses."""
    
    help = 'Add IP addresses to the BlockedIP list'

    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            'ip_addresses',
            nargs='+',
            type=str,
            help='IP addresses to block (supports IPv4 and IPv6)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force add IP without confirmation'
        )

    def handle(self, *args, **options):
        """Handle the command execution."""
        ip_addresses = options['ip_addresses']
        force = options['force']
        
        blocked_ips = []
        already_blocked = []
        invalid_ips = []
        
        for ip_str in ip_addresses:
            ip_str = ip_str.strip()
            
            # Validate IP address format
            try:
                # This will raise ValueError if invalid
                ipaddress.ip_address(ip_str)
            except ValueError:
                invalid_ips.append(ip_str)
                continue
            
            # Check if IP is already blocked
            if BlockedIP.objects.filter(ip_address=ip_str).exists():
                already_blocked.append(ip_str)
                continue
            
            blocked_ips.append(ip_str)
        
        # Report invalid IPs
        if invalid_ips:
            self.stdout.write(
                self.style.ERROR(
                    f"Invalid IP addresses (skipped): {', '.join(invalid_ips)}"
                )
            )
        
        # Report already blocked IPs
        if already_blocked:
            self.stdout.write(
                self.style.WARNING(
                    f"Already blocked: {', '.join(already_blocked)}"
                )
            )
        
        # If no valid IPs to block, exit
        if not blocked_ips:
            self.stdout.write(
                self.style.WARNING("No new IP addresses to block.")
            )
            return
        
        # Show what will be blocked
        self.stdout.write(
            self.style.NOTICE(
                f"IP addresses to block: {', '.join(blocked_ips)}"
            )
        )
        
        # Confirm before blocking (unless --force is used)
        if not force:
            confirm = input("Do you want to proceed? (y/N): ")
            if confirm.lower() not in ['y', 'yes']:
                self.stdout.write(
                    self.style.WARNING("Operation cancelled.")
                )
                return
        
        # Block the IPs
        successfully_blocked = []
        failed_to_block = []
        
        for ip_str in blocked_ips:
            try:
                blocked_ip, created = BlockedIP.objects.get_or_create(
                    ip_address=ip_str
                )
                if created:
                    successfully_blocked.append(ip_str)
                else:
                    already_blocked.append(ip_str)
            except ValidationError as e:
                failed_to_block.append(f"{ip_str} ({e})")
            except Exception as e:
                failed_to_block.append(f"{ip_str} ({str(e)})")
        
        # Report results
        if successfully_blocked:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully blocked {len(successfully_blocked)} IP(s): "
                    f"{', '.join(successfully_blocked)}"
                )
            )
        
        if failed_to_block:
            self.stdout.write(
                self.style.ERROR(
                    f"Failed to block: {', '.join(failed_to_block)}"
                )
            )
        
        # Summary
        total_blocked = BlockedIP.objects.count()
        self.stdout.write(
            self.style.NOTICE(
                f"Total blocked IPs in database: {total_blocked}"
            )
        )

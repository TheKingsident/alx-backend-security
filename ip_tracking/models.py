from django.db import models

class RequestLog(models.Model):
    """Request log model to track IP addresses and paths."""
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)

    class Meta:
        """Meta options for the RequestLog model."""
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ['-timestamp']
    
    def __str__(self):
        """String representation of the RequestLog instance."""
        return f"{self.ip_address} - {self.path} at {self.timestamp}"

class BlockedIP(models.Model):
    """Model to store blocked IP addresses."""
    ip_address = models.GenericIPAddressField(unique=True)

    class Meta:
        """Meta options for the BlockedIP model."""
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
    
    def __str__(self):
        """String representation of the BlockedIP instance."""
        return f"{self.ip_address}"
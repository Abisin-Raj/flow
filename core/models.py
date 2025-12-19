from django.db import models

# Create your models here.


class Connection(models.Model):
    id = models.AutoField(primary_key=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    src_ip = models.GenericIPAddressField(protocol="both", unpack_ipv4=True)
    src_port = models.PositiveIntegerField()
    dst_ip = models.GenericIPAddressField(protocol="both", unpack_ipv4=True)
    dst_port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10)
    status = models.CharField(max_length=20, blank=True)
    pid = models.IntegerField(null=True, blank=True, db_index=True)
    ppid = models.IntegerField(null=True, blank=True)
    process_name = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.protocol})"

    class Meta:
        indexes = [
            models.Index(fields=["timestamp"]),
            models.Index(fields=["src_ip"]),
            models.Index(fields=["dst_ip"]),
        ]
        ordering = ["-timestamp"]


class Alert(models.Model):
    id = models.AutoField(primary_key=True)
    src_ip = models.CharField(max_length=100, null=True, blank=True)
    dst_ip = models.CharField(max_length=100, null=True, blank=True)
    dst_port = models.PositiveIntegerField(null=True, blank=True)
    src_country = models.CharField(max_length=100, null=True, blank=True)
    src_city = models.CharField(max_length=100, null=True, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    alert_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, default="medium")
    message = models.TextField()
    connection = models.ForeignKey(
        Connection,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="alerts",
    )

    pid = models.IntegerField(null=True, blank=True)
    process_name = models.CharField(max_length=200, blank=True)
    resolved = models.BooleanField(default=False)

    category = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return f"[{self.severity}] {self.alert_type}: {self.message[:50]}"

    class Meta:
        indexes = [
            models.Index(fields=["timestamp"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["alert_type"]),
            models.Index(fields=["src_ip"]),
        ]
        ordering = ["-timestamp"]


class QuarantinedFile(models.Model):
    id = models.AutoField(primary_key=True)
    filename = models.CharField(max_length=255)
    original_path = models.TextField()
    quarantine_path = models.TextField(blank=True)
    reason = models.TextField(blank=True)

    # exact hash
    sha256 = models.CharField(max_length=64, blank=True)

    # fuzzy hash (TLSH string)
    tlsh = models.CharField(max_length=128, blank=True)

    # link to known malware signature, if any
    matched_signature = models.ForeignKey(
        "MalwareSignature",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="quarantined_files",
    )

    # distance from fuzzy match, smaller means closer
    match_distance = models.IntegerField(null=True, blank=True)

    # exact, fuzzy, or empty
    match_type = models.CharField(max_length=16, blank=True)

    detected_at = models.DateTimeField(auto_now_add=True)
    restored = models.BooleanField(default=False)
    deleted = models.BooleanField(default=False)

    def __str__(self):
        return (
            f"{self.filename} ({self.sha256[:8]}...)" if self.sha256 else self.filename
        )

    class Meta:
        indexes = [
            models.Index(fields=["sha256"]),
            models.Index(fields=["detected_at"]),
        ]
        ordering = ["-detected_at"]


class MalwareSignature(models.Model):
    """
    Signature database for known malware samples.
    Supports exact SHA256 match and fuzzy TLSH match.
    """
    id = models.AutoField(primary_key=True)
    sha256 = models.CharField(max_length=64, unique=True)
    tlsh = models.CharField(max_length=80, blank=True, null=True)

    family = models.CharField(max_length=128, blank=True)
    severity = models.CharField(max_length=32, default="high")
    description = models.TextField(blank=True, null=True)
    source = models.CharField(max_length=128, blank=True)
    added_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        label = self.family or "Unknown"
        return f"{label} ({self.sha256})"




class WatchedFolder(models.Model):
    id = models.AutoField(primary_key=True)
    path = models.CharField(max_length=500, unique=True)
    recursive = models.BooleanField(default=True)
    auto_quarantine = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        mode = "auto-quarantine" if self.auto_quarantine else "detect-only"
        state = "enabled" if self.enabled else "disabled"
        return f"{self.path} [{mode}, {state}]"


class AppSetting(models.Model):
    """
    Simple key-value settings table for desktop UI settings.
    Use string keys. Values stored as text and parsed by the API.
    """
    id = models.AutoField(primary_key=True)
    key = models.CharField(max_length=128, unique=True)
    value = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.key}={self.value}"


class BlockedIp(models.Model):
    id = models.AutoField(primary_key=True)
    ip = models.GenericIPAddressField(protocol="both", unpack_ipv4=True, unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True)

    def __str__(self):
        return f"{self.ip} (blocked {self.blocked_at})"

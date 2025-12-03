from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings

class User(AbstractUser):
    """
    Custom User model extending Django's AbstractUser.
    Includes role-based fields and profile information.
    """
    is_admin = models.BooleanField(default=False, help_text="Designates whether the user is an admin.")
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)

    # Making email unique and required is common practice for modern auth
    email = models.EmailField(unique=True)

    # Define related_name to avoid conflicts with the default User model
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='tasks_user_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='tasks_user_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

    def __str__(self):
        return self.username


class Task(models.Model):
    """
    The core Task model representing a unit of work.
    """
    PRIORITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
    ]

    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    
    priority = models.CharField(
        max_length=10, 
        choices=PRIORITY_CHOICES, 
        default='MEDIUM'
    )
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default='PENDING'
    )

    # Dates
    start_date = models.DateField(null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)
    
    # Relationships
    # 'related_name' allows you to access these from the User side (e.g., user.created_tasks.all())
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='created_tasks'
    )
    assigned_to = models.ManyToManyField(
        settings.AUTH_USER_MODEL, 
        related_name='assigned_tasks',
        blank=True
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class ChecklistItem(models.Model):
    """
    Sub-steps or TODO items within a specific Task.
    """
    task = models.ForeignKey(
        Task, 
        on_delete=models.CASCADE, 
        related_name='checklist'
    )
    text = models.CharField(max_length=255)
    is_completed = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.text} ({'Done' if self.is_completed else 'Pending'})"


class Attachment(models.Model):
    """
    Files or Links attached to a Task.
    """
    task = models.ForeignKey(
        Task, 
        on_delete=models.CASCADE, 
        related_name='attachments'
    )
    # Allows uploading a file OR providing a link (or both)
    # file = models.FileField(upload_to='task_attachments/', blank=True, null=True)
    link = models.URLField(blank=True, null=True, help_text="External link URL")
    
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # if self.file:
        #     return f"File: {self.file.name}"
        return f"Link: {self.link}"
from django.contrib import admin
from .models import Task, Attachment, ChecklistItem

# Register your models here.

admin.site.register(Task)
admin.site.register(Attachment)
admin.site.register(ChecklistItem)
from django.contrib import admin
from .models import EncryptedFile

@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
    list_display = ['original_filename', 'user', 'encryption_type', 'status', 'uploaded_at']
    list_filter = ['encryption_type', 'status']

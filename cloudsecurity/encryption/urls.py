from django.urls import path
from . import views

app_name = 'encryption'

urlpatterns = [
    path('upload/', views.upload_file_view, name='upload'),
    path('download/<uuid:file_id>/', views.download_file_view, name='download'),
    path('decrypt/<uuid:file_id>/', views.decrypt_file_view, name='decrypt'),
    path('verify/<uuid:file_id>/', views.verify_integrity_view, name='verify_integrity'),
    path('api/stats/', views.encryption_stats_api, name='stats_api'),
]

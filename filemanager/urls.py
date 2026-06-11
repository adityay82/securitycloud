from django.urls import path
from . import views

app_name = 'filemanager'

urlpatterns = [
    path('', views.file_list_view, name='list'),
    path('delete/<uuid:file_id>/', views.delete_file_view, name='delete'),
]

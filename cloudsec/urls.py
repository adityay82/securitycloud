from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('authentication.urls', namespace='authentication')),
    path('dashboard/', include('dashboard.urls', namespace='dashboard')),
    path('files/', include('filemanager.urls', namespace='filemanager')),
    path('encryption/', include('encryption.urls', namespace='encryption')),
    path('ml/', include('ml_module.urls', namespace='ml_module')),
    path('audit/', include('audit.urls', namespace='audit')),
    # REST API v1
    path('api/v1/', include('api.urls', namespace='api')),
    # Landing page
    path('', TemplateView.as_view(template_name='landing.html'), name='landing'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

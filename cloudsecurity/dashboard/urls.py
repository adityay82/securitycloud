from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.index_view, name='index'),
    path('users/', views.users_list_view, name='users'),
    path('approve/<uuid:user_id>/', views.approve_user_view, name='approve_user'),
    path('suspend/<uuid:user_id>/', views.suspend_user_view, name='suspend_user'),
    path('api/stats/', views.dashboard_stats_api, name='stats_api'),
]

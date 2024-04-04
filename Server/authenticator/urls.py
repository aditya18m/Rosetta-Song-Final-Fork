from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('google-callback/', views.google_callback, name='google_callback'),
    path('success/', views.success, name='success'),
    path('youtube-playlists/', views.youtube_playlists, name='youtube_playlists'),
]

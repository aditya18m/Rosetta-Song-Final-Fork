from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login, name='login'),
    path('google-callback/', views.google_callback, name='google_callback'),
    path('success/', views.success, name='success'),
    path('youtube-playlists/', views.youtube_playlists, name='youtube_playlists'),
    path('view-spotify-playlists/', views.view_spotify_playlists, name='view_spotify_playlists'),
    path('transfer-playlists/', views.transfer_playlists, name='transfer_playlists'),
]

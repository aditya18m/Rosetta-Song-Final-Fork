from django.contrib import admin
from django.urls import path
from authenticator import views
from django.urls import path, include

urlpatterns = [
    path('', views.home, name='home'),
    path('admin/', admin.site.urls),
    path('authorize-spotify/', views.authorize_spotify, name='authorize_spotify'),  # URL for initiating Spotify authorization
    path('callback/', views.handle_callback, name='callback'),
    path('', include('authenticator.urls')),
    path('google_sign_in/', views.google_sign_in, name='google_sign_in'),
    path('social-auth/', include('social_django.urls', namespace='social')),
    path('select_destination/', views.select_destination, name='select_destination'),
    path('view_spotify_playlists/', views.view_spotify_playlists, name='view_spotify_playlists'),
    path('transfer_playlists', views.transfer_playlists, name = 'transfer_playlists'),
    path('create_yt_playlists', views.create_yt_playlist, name='create_yt_playlists'),
]

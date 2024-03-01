from django.contrib import admin
from django.urls import path
from authenticator import views

urlpatterns = [
    path('', views.home, name='home'),
    path('admin/', admin.site.urls),
    path('authorize-spotify/', views.authorize_spotify, name='authorize_spotify'),  # URL for initiating Spotify authorization
    path('callback/', views.handle_callback, name='callback'),
    path('google-sign-in/', views.google_sign_in, name='google_sign_in'),
    path('google-callback/', views.google_callback, name='google_callback'),
]

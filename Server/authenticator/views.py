from django.shortcuts import redirect
from django.urls import reverse
from django.http import HttpResponse
from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from social_django.models import UserSocialAuth
from social_django.utils import load_strategy, load_backend
import secrets
import string
import hashlib
import base64
import requests
import urllib.parse
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

CLIENT_ID = 'bf6f8c7448d5421dae2a1867a69819d3'

REDIRECT_URI = 'http://localhost:8000/callback/'
TOKEN_URI = 'https://accounts.spotify.com/api/token'
USER_INFO_URI = 'https://api.spotify.com/v1/me'
scope = 'user-read-private user-read-email'
# SOURCE = ''
# DESTINATION = ''


def home(request):
    return render(request, 'home.html')

def google_callback(request):
    return redirect('success')

@login_required
def success(request):
    # Once authenticated, users are redirected here. You can display a success message,
    # user info, or proceed with further actions like interacting with the YouTube Music API.

    # Example: Fetching Google OAuth2 tokens stored by 'social-auth-app-django'
    user_social_auth = UserSocialAuth.objects.get(user=request.user, provider='google-oauth2')
    access_token = user_social_auth.extra_data['access_token']

    # Use access_token to interact with APIs that require OAuth2 authentication.

    # Use access_token to interact with APIs that require OAuth2 authentication.
    # Redirect to the YouTube playlists view
    return redirect('youtube_playlists')
    

def generate_code_verifier(length):
    #generates random string for code verification.
    characters = string.ascii_letters + string.digits + '-._~'
    return ''.join(secrets.choice(characters) for _ in range(length))

def sha256(plain):
    # calculates the SHA256 hash
    return hashlib.sha256(plain.encode()).digest()

def base64encode(input):
    # base64 encode input
    encoded = base64.urlsafe_b64encode(input).rstrip(b'=')
    return encoded.decode()

def authorize_spotify(request):
    code_verifier = generate_code_verifier(64)
    request.session['code_verifier'] = code_verifier
    code_challenge = base64encode(sha256(code_verifier))
    spotify_auth_url = 'https://accounts.spotify.com/authorize'
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': scope,
        'code_challenge_method': 'S256',
        'code_challenge': code_challenge,
    }
    auth_url = f'{spotify_auth_url}?{urllib.parse.urlencode(params)}'
    print("AUth url: " ,auth_url)

    return redirect(auth_url)

def google_sign_in(request):
    """
    Initiates the Google sign-in process and returns a URL to open in a popup.
    """
    strategy = load_strategy(request)
    backend = load_backend(strategy=strategy, name='google-oauth2', redirect_uri=None)
    redirect_uri = reverse('google_callback')
    auth_url = backend.auth_url(redirect_uri=redirect_uri)
    return render(request, 'google_sign_in.html', {'auth_url': auth_url})

@login_required
def google_callback(request):
    """
    Handles the callback from Google. This view captures the OAuth token and stores it.
    """
    user = request.user
    social_user = user.social_auth.get(provider='google-oauth2')
    token = social_user.extra_data['access_token']

    # Store the token in the session or database as needed
    request.session['google_token'] = token

    # Redirect or respond as needed, perhaps showing a success message or redirecting to another page
    return HttpResponse("Google sign-in successful, token stored.")

def handle_callback(request):
    authorization_code = request.GET.get('code')
    print("entering handle_callback!")
    payload = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': 'http://localhost:8000/callback/',
        'client_id': CLIENT_ID,
        'code_verifier': request.session.get('code_verifier')
    }
    response = requests.post(TOKEN_URI, data=payload)
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get('access_token')
        if access_token:
            request.session['access_token'] = access_token
            print ("got valid access token")
            print(access_token)
            headers = {
                'Authorization': f'Bearer {access_token}'
            }
            user_info_response = requests.get(USER_INFO_URI, headers=headers)
            print(user_info_response.status_code)
            if user_info_response.status_code == 200:
                return redirect('view_spotify_playlists')
            else:
                return HttpResponse('Failed to fetch user info from Spotify', status=user_info_response.status_code)
        else:
            return HttpResponse('Failed to obtain access token from Spotify', status=400)
    else:
        return HttpResponse('Token exchange failed', status=response.status_code)
    
@login_required
def youtube_playlists(request):
    user_social_auth = UserSocialAuth.objects.get(user=request.user, provider='google-oauth2')
    access_token = user_social_auth.extra_data['access_token']
    
    # Convert the access token to credentials
    credentials = Credentials(token=access_token)

    try:
        # Build the YouTube client using the credentials
        youtube = build('youtube', 'v3', credentials=credentials)

        # Fetch the playlists
        response = youtube.playlists().list(
            part="id,snippet",
            maxResults=25,
            mine=True
        ).execute()

        playlists = response.get('items', [])
        return render(request, 'youtube_playlists.html', {'playlists': playlists})

    except HttpError as e:
        # Handle HTTP errors from the API here
        error_message = f'An error occurred: {e.resp.status}, {e.content}'
        return HttpResponse(error_message, status=500)

# @login_required
def view_spotify_playlists(request):
    access_token = request.session.get('access_token', '')
    playlists_endpoint = 'https://api.spotify.com/v1/me/playlists'
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.get(playlists_endpoint, headers=headers)

    if response.status_code == 200:
        playlists_data = response.json()

        playlists_info = []
        for playlist in playlists_data.get('items', []):
            playlists_info.append({
                'name': playlist.get('name'),
                'owner': playlist.get('owner', {}).get('display_name'),
                'public': 'Public' if playlist.get('public') else 'Private'
            })
        return render(request, 'spotify_playlists.html', {'playlists': playlists_info})
    else:
        return render(request, 'error.html', {'message': 'Failed to fetch playlists from Spotify'})


def select_destination(request):
    return render(request, 'select_destination.html')

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
from urllib.parse import unquote

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

CLIENT_ID = 'bf6f8c7448d5421dae2a1867a69819d3'

scopes = ["https://www.googleapis.com/auth/youtube", "https://www.googleapis.com/auth/youtube.force-ssl", 
          "https://www.googleapis.com/auth/youtubepartner"]

REDIRECT_URI = 'http://localhost:8000/callback/'
TOKEN_URI = 'https://accounts.spotify.com/api/token'
USER_INFO_URI = 'https://api.spotify.com/v1/me'
scope = 'user-read-private user-read-email'

def home(request):
    return render(request, 'home.html')
    
def login(request):
    return render(request, 'login.html')

def google_callback(request):
    return redirect('success')



@login_required
def success(request):
    print("success")
    print(request.session['source'])
    print("source \\")
    if('source' not in request.session):
        print("source was empty, setting it to youtube!")
        request.session['source']='youtube'
    # Once authenticated, users are redirected here. You can display a success message,
    # user info, or proceed with further actions like interacting with the YouTube Music API.

    # Example: Fetching Google OAuth2 tokens stored by 'social-auth-app-django'
    user_social_auth = UserSocialAuth.objects.get(user=request.user, provider='google-oauth2')
    access_token = user_social_auth.extra_data['access_token']

    # Use access_token to interact with APIs that require OAuth2 authentication.

    # Use access_token to interact with APIs that require OAuth2 authentication.
    # Redirect to the YouTube playlists view
    if request.session['source'] == 'youtube':
        return redirect('select_destination')  
    else:
        return redirect(view_spotify_playlists)
    # return redirect('youtube_playlists')   

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
    
    if('source' not in request.session):
        print("source was empty, setting it to spotify!")
        request.session['source']='spotify'
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
    print("Auth url: " ,auth_url)

    return redirect(auth_url)
    

def google_sign_in(request):
    """
    Initiates the Google sign-in process and returns a URL to open in a popup.
    """
    if('source' not in request.session):
        print("source was empty, setting it to youtube!")
        request.session['source']='youtube'
    print("google_sign_in")
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
    if('source' not in request.session):
        print("source was empty, setting it to youtube!")
        request.session['source']='youtube'
    user = request.user
    social_user = user.social_auth.get(provider='google-oauth2')
    token = social_user.extra_data['access_token']

    # Store the token in the session or database as needed
    request.session['google_token'] = token
    print("google_callback")
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
                if request.session.get('source') == 'spotify':
                    return redirect('select_destination')
                    # return redirect('select_destination.html')
                else:
                    return render(request, 'transfer.html')
            else:
                return HttpResponse('Failed to fetch user info from Spotify', status=user_info_response.status_code)
        else:
            return HttpResponse('Failed to obtain access token from Spotify', status=400)
    else:
        return HttpResponse('Token exchange failed', status=response.status_code)
    
@login_required
def youtube_playlists(request):
    print("redirected to youtube_playlists")
    user_social_auth = UserSocialAuth.objects.get(user=request.user, provider='google-oauth2')
    access_token = user_social_auth.extra_data['access_token']
    
    # Convert the access token to credentials
    credentials = Credentials(token=access_token)
    print("entered youtube")
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
        for playlist in playlists:
            print("Playlist ID:", playlist['id'])
            print("Playlist Title:", playlist['snippet']['title'])
            print("---------")  

        return render(request, 'login.html', {'playlists_to': playlists})
        #return render(request, 'login.html', {'playlists_to': playlists})

    except HttpError as e:
        # Handle HTTP errors from the API here
        error_message = f'An error occurred: {e.resp.status}, {e.content}'
        return HttpResponse(error_message, status=500)


from django.shortcuts import render

def view_spotify_playlists(request):
    print("entered view playlists")
    access_token = request.session.get('access_token', '')
    headers = {'Authorization': f'Bearer {access_token}'}

    playlists_response = requests.get('https://api.spotify.com/v1/me/playlists', headers=headers)

    if playlists_response.status_code == 200:
        playlists_data = playlists_response.json()
        playlists_info = []

        for playlist in playlists_data.get('items', []):
            playlist_id = playlist.get('id')
            tracks_endpoint = f'https://api.spotify.com/v1/playlists/{playlist_id}/tracks'
            tracks_response = requests.get(tracks_endpoint, headers=headers)

            if tracks_response.status_code == 200:
                tracks_data = tracks_response.json()
                track_items = tracks_data.get('items', [])
                
                track_names = []
                for item in track_items:
                    track = item.get('track', {})
                    if track and 'name' in track:
                        track_names.append(track['name'])

                playlists_info.append({
                    'name': playlist.get('name'),
                    'tracks': track_names
                })
                print(playlists_info)
        return render(request, 'transfer.html', {'playlists': playlists_info})
    else:
        return render(request, 'error.html', {'message': 'Failed to fetch playlists from Spotify'})





def select_destination(request):
    return render(request, 'select_destination.html')


def transfer_playlists(request):
    if request.method == 'POST':
        if request.session['source'] == 'spotify':
            playlist_names = request.POST.getlist('playlist_names')
            playlists_tracks = {}

            for playlist_name in playlist_names:
                tracks_string = request.POST.get('tracks_' + playlist_name, '')
                tracks = tracks_string.split('|') if tracks_string else []
                playlists_tracks[playlist_name] = tracks
                return (create_yt_playlist(request,playlist_name, tracks)) 

        else:
            pass
            # implement yt transfer
    else:
        return HttpResponse('Invalid request method.', status=405)

def create_yt_playlist(request, playlist_name, tracks):
    try:
        user_social_auth = UserSocialAuth.objects.get(user=request.user, provider='google-oauth2')
        access_token = user_social_auth.extra_data['access_token']
        credentials = Credentials(token=access_token)
        youtube = build('youtube', 'v3', credentials=credentials)
        playlist_response = youtube.playlists().insert(
            part="snippet,status",
            body={
                "snippet": {
                    "title": playlist_name,
                    "description": "Playlist created via Rosetta Song",
                    "tags": ["sample playlist", "API call"],
                    "defaultLanguage": "en",
                },
                "status": {
                    "privacyStatus": "private"
                }
            }
        ).execute()

        playlist_id = playlist_response["id"]

        for track_name in tracks:
            video_id = search_youtube_video(youtube, track_name)
            if video_id:
                youtube.playlistItems().insert(
                    part="snippet",
                    body={
                        "snippet": {
                            "playlistId": playlist_id,
                            "resourceId": {
                                "kind": "youtube#video",
                                "videoId": video_id
                            }
                        }
                    }
                ).execute()
        print(playlist_name)
        return render(request, 'transferred.html', {'playlist_name': playlist_name, 'playlist_id': playlist_id})

    except HttpError as e:
        return render(request, 'error.html', {'message': f'An error occurred: {e}'})

def search_youtube_video(youtube, track_name):
    search_response = youtube.search().list(
        q=track_name,
        part="id",
        maxResults=1,
        type="video"
    ).execute()

    search_results = search_response.get("items", [])
    if not search_results:
        return None  

    return search_results[0]["id"]["videoId"]
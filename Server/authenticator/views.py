"""
views.py
"""
import secrets
import string
import hashlib
import base64
import urllib.parse
import requests

from django.shortcuts import render, redirect
from django.urls import reverse
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required

from social_django.models import UserSocialAuth
from social_django.utils import load_strategy, load_backend
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

CLIENT_ID = 'bf6f8c7448d5421dae2a1867a69819d3'
REDIRECT_URI = 'http://localhost:8000/callback/'
TOKEN_URI = 'https://accounts.spotify.com/api/token'
USER_INFO_URI = 'https://api.spotify.com/v1/me'

SCOPES = [
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/youtubepartner"
]

SCOPE = 'user-read-private user-read-email'

def home(request):
    """
    Render the home page.
    """
    return render(request, 'home.html')

def login(request):
    """
    Handle login requests.
    """
    request.session['source'] = ''
    return render(request, 'login.html')

@login_required
def success(request):
    """
    Handle success after login, redirect based on session source.
    """
    if not request.session.get('source'):
        print("source was empty, setting it to youtube!")
        request.session['source'] = 'youtube'
    if request.session['source'] == 'youtube':
        return redirect('select_destination')
    return redirect('view_spotify_playlists')

def generate_code_verifier(length=64):
    """
    Generate a secure random string for the code verifier.
    """
    characters = string.ascii_letters + string.digits + '-._~'
    return ''.join(secrets.choice(characters) for _ in range(length))

def sha256(plain):
    """
    Calculate the SHA256 hash of the input.
    """
    return hashlib.sha256(plain.encode()).digest()

def base64encode(input):
    """
    Base64 encode the input bytes.
    """
    encoded = base64.urlsafe_b64encode(input).rstrip(b'=')
    return encoded.decode()

def authorize_spotify(request):
    """
    Begin Spotify authorization process and redirect user to Spotify auth URL.
    """
    if not request.session.get('source'):
        print("source was empty, setting it to spotify!")
        request.session['source'] = 'spotify'

    code_verifier = generate_code_verifier()
    request.session['code_verifier'] = code_verifier
    code_challenge = base64encode(sha256(code_verifier))
    spotify_auth_url = 'https://accounts.spotify.com/authorize'

    spotify_scope='user-read-private user-read-email playlist-modify-public playlist-modify-private'
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': spotify_scope,
        'code_challenge_method': 'S256',
        'code_challenge': code_challenge,
    }
    auth_url = f'{spotify_auth_url}?{urllib.parse.urlencode(params)}'
    return redirect(auth_url)

@login_required
def google_callback(request):
    """
    Handle the callback from Google OAuth, store the access token.
    """
    if not request.session.get('source'):
        print("source was empty, setting it to youtube!")
        request.session['source'] = 'youtube'

    user = request.user
    social_user = user.social_auth.get(provider='google-oauth2')
    token = social_user.extra_data['access_token']
    request.session['google_token'] = token
    return HttpResponse("Google sign-in successful, token stored.")

def google_sign_in(request):
    """
    Initiates the Google sign-in process and returns a URL to open in a popup.
    """
    if request.session['source'] == '':
        print("source was empty, setting it to youtube!")
        request.session['source']='youtube'
    print("google_sign_in")
    strategy = load_strategy(request)
    backend = load_backend(strategy=strategy, name='google-oauth2', redirect_uri=None)
    redirect_uri = reverse('google_callback')
    auth_url = backend.auth_url(redirect_uri=redirect_uri)
    return render(request, 'google_sign_in.html', {'auth_url': auth_url})


def handle_callback(request):
    """
    Handle the OAuth2.0 callback after the authorization request, processing the authorization code.
    This function exchanges the code for an access token and fetches user info from Spotify.
    """
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
                return redirect(youtube_playlists)

            return HttpResponse('Failed to fetch user info from Spotify', status=user_info_response.status_code)

        return HttpResponse('Failed to obtain access token from Spotify', status=400)

    return HttpResponse('Token exchange failed', status=response.status_code)

@login_required
def youtube_playlists(request):
    """
    Display a list of YouTube playlists associated with the authenticated user's account.
    This function fetches playlists using the YouTube Data API.
    """
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

        playlists = [{
            'id': item['id'],
            'title': item['snippet']['title']
        } for item in response.get('items', [])]

        for playlist in playlists:
            print("Playlist ID:", playlist['id'])
            print("Playlist Title:", playlist['title'])
            print("---------")

        # Make sure to pass the correct variable to the template
        return render(request, 'yt_playlists.html', {'playlists': playlists})
    except HttpError as e:
        # Handle HTTP errors from the API here
        error_message = f'An error occurred: {e.resp.status}, {e.content}'
        return HttpResponse(error_message, status=500)



def select_destination(request):
    """
    Render the page for selecting the destination after user login.
    """
    return render(request, 'select_destination.html')


@login_required
def transfer_playlists(request):
    """
    Handle the transfer of playlists between YouTube and Spotify depending on the session source.
    This function supports transferring from YouTube to Spotify and vice versa.
    """
    if request.method == 'POST':
        source = request.session.get('source')

        if source == 'youtube':
            youtube_playlist_id = request.POST.get('youtube_playlist_id')
            youtube_playlist_title=request.POST.get('youtube_playlist_title_' + youtube_playlist_id)

            print(f"Attempting to transfer YouTube playlist:{youtube_playlist_title}") #Debug output

            youtube_tracks = fetch_youtube_playlist_tracks(request.user, youtube_playlist_id)
            access_token = request.session.get('access_token')
            spotify_user_id = fetch_spotify_user_id(access_token)

            spotify_playlist_id = create_spotify_playlist(access_token, spotify_user_id, youtube_playlist_title)

            successful_tracks = []
            failed_tracks = []

            for track_name in youtube_tracks:
                spotify_track_id = search_spotify_for_track(access_token, track_name)
                if spotify_track_id:
                    track_details = get_spotify_track_details(access_token, spotify_track_id)
                    successful_tracks.append(track_details)
                    print(f"Adding track ID {spotify_track_id} to playlist")
                    add_tracks_to_spotify_playlist(access_token, spotify_playlist_id, [spotify_track_id])
                else:
                    failed_tracks.append({'name': track_name, 'artist': 'Unknown'})

            return render(request, 'transferred.html', {
                'message': "Transfer Completed",
                'playlist_name': youtube_playlist_title,
                'spotify_playlist_id': spotify_playlist_id,
                'successful_tracks': successful_tracks,
                'failed_tracks': failed_tracks
            })
        elif source == 'spotify':
            playlist_names = request.POST.getlist('playlist_names')
            for playlist_name in playlist_names:
                tracks_string = request.POST.get('tracks_' + playlist_name, '')
                tracks_with_artists=[track.split(',') for track in tracks_string.split('|') if track]
                tracks = [{'name': track[0], 'artist': track[1] if len(track) > 1 else None} for track in tracks_with_artists]
                create_yt_playlist(request, playlist_name, tracks)
            return JsonResponse({'status': 'success'})

def get_spotify_track_details(access_token, track_id):
    headers = {'Authorization': f'Bearer {access_token}'}
    track_info_url = f'https://api.spotify.com/v1/tracks/{track_id}'
    response = requests.get(track_info_url, headers=headers)
    if response.status_code == 200:
        track_data = response.json()
        return {
            'name': track_data.get('name', 'Unknown Track'),
            'artist': track_data['artists'][0]['name'] if track_data['artists'] else 'Unknown Artist'
        }
    return {'name': 'Track info unavailable', 'artist': 'Unknown Artist'}
 
def fetch_youtube_playlist_tracks(user, playlist_id):
    """
    Fetch and return the titles of tracks from a YouTube playlist specified by its ID.
    """
    try:
        social_auth = user.social_auth.get(provider='google-oauth2')
        credentials = Credentials(token=social_auth.extra_data['access_token'])
        youtube = build('youtube', 'v3', credentials=credentials)
        request = youtube.playlistItems().list(
            part="snippet",
            playlistId=playlist_id,
            maxResults=50
        )
        response = request.execute()
        track_names = [item['snippet']['title'] for item in response.get('items', [])]
        print("YouTube Track Names:", track_names)
        
        return track_names
    except HttpError as e:
        print(f"An error occurred: {e}")
        return []


def fetch_spotify_user_id(access_token):
    """
    Fetch and return the Spotify user ID using the provided access token.
    """
    # Fetch Spotify user ID.
    response = requests.get(USER_INFO_URI, headers={'Authorization': f'Bearer {access_token}'})
    response_json = response.json()
    return response_json['id']

def create_spotify_playlist(access_token, user_id, playlist_name):
    """
    Create a Spotify playlist for a user specified by user_id, with a given name, and return the playlist ID.
    """
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    payload = {'name': playlist_name, 'public': True}  # Ensure public is True if you want the playlist to be visible

    print(f"Creating Spotify playlist with name: {playlist_name}")  # Debug output

    response = requests.post(f'https://api.spotify.com/v1/users/{user_id}/playlists', headers=headers, json=payload)
    if response.status_code == 201:
        response_json = response.json()
        playlist_id = response_json.get('id')
        print(f"Playlist created with ID: {playlist_id}")  # Debug output
        return playlist_id
    print(f"Failed to create playlist. Status Code: {response.status_code}. Response: {response.text}")  # Debug output
    response.raise_for_status()


def view_spotify_playlists(request):
    """
    Display Spotify playlists for the authenticated user by fetching them from the Spotify Web API.
    """
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

                tracks_info = []
                for item in track_items:
                    track = item.get('track', {})
                    if track:
                        track_name = track.get('name', 'Unknown track')
                        artist_name = track['artists'][0]['name'] if track['artists'] else 'Unknown artist'
                        track_info = f"{track_name} by {artist_name}"
                        tracks_info.append(track_info)

                playlists_info.append({
                    'name': playlist.get('name'),
                    'tracks': tracks_info
                })
                print(playlists_info)
        return render(request, 'transfer.html', {'playlists': playlists_info})
    return render(request, 'error.html', {'message': 'Failed to fetch playlists from Spotify'})


def search_spotify_for_track(access_token, track_name):
    headers = {'Authorization': f'Bearer {access_token}'}
    params = {'q': track_name, 'type': 'track', 'limit': 1}
    response = requests.get('https://api.spotify.com/v1/search', headers=headers, params=params)
    response_json = response.json()
    tracks = response_json.get('tracks', {}).get('items', [])
    
    # Debugging: print out Spotify search results
    if tracks:
        print(f"Found on Spotify: {tracks[0]['name']} by {tracks[0]['artists'][0]['name']}")
        return tracks[0]['id']
    else:
        print(f"No Spotify result for: {track_name}")
    return None


def add_tracks_to_spotify_playlist(access_token, playlist_id, track_ids):
    """
    Add tracks to a Spotify playlist specified by playlist_id using the provided track IDs.
    """
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    uris = [f'spotify:track:{track_id}' for track_id in track_ids]
    payload = {'uris': uris}
    response = requests.post(f'https://api.spotify.com/v1/playlists/{playlist_id}/tracks', headers=headers, json=payload)
    # Debugging: check the response status and content
    print(f"Add to Playlist Response Status: {response.status_code}, Content: {response.json()}")
    return response.json()


def check_spotify_playlist(access_token, playlist_id):
    """
    Check if a Spotify playlist exists and return its status and information.
    """
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f'https://api.spotify.com/v1/playlists/{playlist_id}', headers=headers)

    if response.status_code == 200:
        print("Playlist exists and here's the data:", response.json())
        return True, response.json()
    print("Failed to find playlist:", response.status_code)
    return False, response.json()


def create_yt_playlist(request, playlist_name, tracks):
    """
    Create a YouTube playlist with the specified name and tracks, and render the resulting page.
    """
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

        for track in tracks:
            track_name = track['name']
            artist_name = track.get('artist')
            search_query = track_name
            if artist_name:
                search_query += f" {artist_name}"
            video_id = search_youtube_video(youtube, search_query)
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


def search_youtube_video(youtube, query):
    """
    Search for a video on YouTube using the provided query.
    """
    print("search query: ", query)
    search_response = youtube.search().list(
        q=query,
        part="id",
        maxResults=1,
        type="video"
    ).execute()

    search_results = search_response.get("items", [])
    if not search_results:
        return None

    return search_results[0]["id"]["videoId"]

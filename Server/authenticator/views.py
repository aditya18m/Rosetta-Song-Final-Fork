from django.shortcuts import redirect
from django.urls import reverse
from django.http import HttpResponse
from django.shortcuts import render
from django.http import HttpResponse
import secrets
import string
import hashlib
import base64
import requests
import urllib.parse

CLIENT_ID = '06826329cc9549d5a68251f7b77f694f'
REDIRECT_URI = 'http://localhost:8000/callback/'
TOKEN_URI = 'https://accounts.spotify.com/api/token'
USER_INFO_URI = 'https://api.spotify.com/v1/me'
scope = 'user-read-private user-read-email'



def home(request):
    return render(request, 'home.html')

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
            if user_info_response.status_code == 200:
                user_info = user_info_response.json()
                display_name = user_info.get('display_name')
                username = user_info.get('id')
                return render(request, 'user_info.html', {'display_name': display_name, 'username': username})
            else:
                return HttpResponse('Failed to fetch user info from Spotify', status=user_info_response.status_code)
        else:
            return HttpResponse('Failed to obtain access token from Spotify', status=400)
    else:
        return HttpResponse('Token exchange failed', status=response.status_code)
        
    

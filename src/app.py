import time
import os
import pickle
import base64
import mimetypes
import json
from flask import Flask, redirect, url_for, session, request, render_template
from flask_oauthlib.client import OAuth
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'

# Configuração OAuth
with open('credentials.json', 'r') as f:
    credentials_info = json.load(f)

flow = Flow.from_client_config(
    credentials_info,
    scopes=[
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.settings.sharing',
        'https://www.googleapis.com/auth/admin.directory.user.readonly'
    ],
    redirect_uri='http://localhost:5000/callback'
)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    return redirect(url_for('check_emails'))

@app.route('/check_emails')
def check_emails():
    if 'credentials' not in session:
        return redirect('login')

    creds = Credentials(**session['credentials'])
    gmail_service = build('gmail', 'v1', credentials=creds)

    try:
        user_info_service = build('oauth2', 'v2', credentials=creds)
        user_info = user_info_service.userinfo().get().execute()
        user_email = user_info['email']
        
        results = gmail_service.users().messages().list(userId='me', q='has:attachment').execute()
        messages = results.get('messages', [])

        prohibited_types = ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/xml', 'text/css']

        for message in messages:
            msg = gmail_service.users().messages().get(userId='me', id=message['id']).execute()
            for part in msg['payload'].get('parts', []):
                if part['filename']:
                    mime_type = part['mimeType']
                    if mime_type in prohibited_types:
                        print(f'Found prohibited attachment: {part["filename"]} with MIME type {mime_type}')
                        delegate_mailbox(gmail_service, user_email, 'admin@getmoveis.com.br')
                        return f'Prohibited attachment found and reported in user {user_email} mailbox'

        return 'No prohibited attachments found.'
    except Exception as e:
        print(f'An error occurred: {e}')
        return 'An error occurred.'

def delegate_mailbox(gmail_service, user_email, delegate_email):
    try:
        delegate_settings = {
            'delegateEmail': delegate_email
        }
        gmail_service.users().settings().delegates().create(userId='me', body=delegate_settings).execute()
        print(f"Delegated {user_email}'s mailbox to {delegate_email}")
    except Exception as error:
        print(f'An error occurred: {error}')

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

if __name__ == '__main__':
    time.sleep(5)
    app.run(host='0.0.0.0', port=5000, debug=False)
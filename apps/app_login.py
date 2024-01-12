
from pymongo.mongo_client import MongoClient
from flask import Flask, redirect, url_for, session, request, jsonify, render_template

from werkzeug.security import generate_password_hash

import jwt
import datetime


from authlib.integrations.flask_client import OAuth
from functools import wraps
import json
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)


with open('client_secret_78372213139-32um8dhc4u3f2av15cqtssbgeu91qgvq.apps.googleusercontent.com.json', 'r') as file:
    google_sec = json.load(file)

# 데이터 출력
print(google_sec)

google_client_id = google_sec['web']['client_id']
google_client_secret = google_sec['web']['client_secret']
google_redirect_uri = google_sec['web']['redirect_uris']

#print(google_client_id)
#print(google_client_secret)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id= google_client_id,
    client_secret=google_client_secret,
    access_token_url=google_sec['web']['token_uri'],
    access_token_params=None,
    authorize_url=google_sec['web']['auth_uri'],
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v3/',
    client_kwargs={'scope': 'openid email profile'},
    #jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
)


@app.route('/')
def homepage():
    session['google_token'] = None
    session['user'] = None
    return 'Welcome to the Google OAuth2 Example! <a href="login">google Login</a>'

@app.route('/login')
def login():
    redirect_uri = url_for('login_callback', _external=True)
    print(redirect_uri)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/callback')
def login_callback():
    token = google.authorize_access_token()
    if token is None:
        return 'login_failed'
    nonce = session.get('nonce')  # Retrieve nonce from session
    user = google.parse_id_token(token, nonce)

    session['google_token'] = token
    session['user'] = user
    print(session["user"])
    user_email = user['email']

    if user['email_verified'] :
        token = jwt.encode(
            {'userId': user['email'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=100)},
            app.config['SECRET_KEY'], algorithm='HS256')
        session['jwt'] = token
        return jsonify({"email":user['email'],
                    "jwt": token,
                    "message": "Success",
                    "name": user['name'],
    "picture": user['picture']}), 200

    else:
        return jsonify({'message':'failed'}), 401



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
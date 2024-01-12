from authlib.jose.errors import InvalidClaimError
from pymongo.mongo_client import MongoClient
from flask import Flask, redirect, url_for, session, request, jsonify, render_template
import uuid
from werkzeug.security import generate_password_hash

import jwt
import datetime
import os

from authlib.integrations.flask_client import OAuth
from functools import wraps
import requests
import json
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

import certifi
mongo_connect = "mongodb+srv://yangjunwon1309:MGACKDnRT2ZrLNBz@mad0.uejylnk.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(mongo_connect, tlsCAFile=certifi.where())

try:
    db = client.users
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)


doc = {
    'userName':'test',
    'password': 'test1234',
    'email' : 'test@gmail.com',
    'userId':'test',
    'jwt':'test',
}


##db.user.insert_one(doc)
##print('success')
##all_users = list(db.user.find({},{'_id':False}))

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
    user_document = db.user.find_one({'email': user_email})
    if user_document is None:
        new_user = {
            'email': user_email,
            'userName': user["name"],
            'password': None,
            'userId': user_email,
            'jwt': None,
        }
        db.user.insert_one(new_user)
        return redirect(url_for('signUp'))
    else:
        token = jwt.encode(
            {'userId': user_document['userId'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=100)},
            app.config['SECRET_KEY'], algorithm='HS256')
        session['jwt'] = token
        return redirect(url_for('main_page'))
    #return f'Hello, {session["user"]["name"]}!, '

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'jwt' in session and session['jwt'] is not None:
            print('token_get')
            token = session['jwt']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
            print(data)
            user_document = db.user.find_one({'email': data['userId']})
            db.user.update_one(
                {'email': session['user']['email']},
                {'$set': {'jwt': token}}
            )
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(user_document, *args, **kwargs)

    return decorated

@app.route('/signUp', methods = ["GET", "POST"])
def signUp():
    if request.method == 'POST':
        user_email = session['user']['email']
        password = request.form['password']
        password  = generate_password_hash(password, method='pbkdf2:sha256')
        user_id = request.form['userId']
        user_name = request.form['userName']

        db.user.update_one(
            {'email': user_email},
            {'$set': {'password': password, 'userId': user_id, 'userName': user_name}}
        )
        return redirect(url_for('login'))

    return render_template('sign_up.html')

@app.route('/main')
@token_required
def main_page(user_document):
    return f'Welcome to the Main Page!'






if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
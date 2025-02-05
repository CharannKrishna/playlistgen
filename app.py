from flask import Flask, render_template, request, jsonify, redirect, session, url_for,make_response
from authlib.integrations.flask_client import OAuth
import bcrypt 
import requests
import base64
import os
import uuid
import json
import sqlite3
from datetime import datetime
import random

app = Flask(__name__)
app.secret_key = os.urandom(24)
oauth = OAuth(app)

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS playlists
                 (id TEXT PRIMARY KEY,
                  user_id INTEGER,
                  name TEXT,
                  songs TEXT,
                  created_at DATETIME,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

init_db()

SPOTIFY_CLIENT_ID = ''
SPOTIFY_CLIENT_SECRET = ''


google = oauth.register(
    name='google',
    client_id='',
    client_secret='',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={'scope': 'openid email profile'},
    access_token_url='https://oauth2.googleapis.com/token',
    client_kwargs={'scope': 'openid email profile'}
)

# User management functions
def get_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    return user

def create_user(username, password):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        # Correct: Keep salt as bytes
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # Store the hashed password as a string
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                 (username, hashed_password.decode('utf-8')))  # Decode here for storage
        conn.commit()
        return c.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

# Authentication routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_user(session['user_id'])
    response = make_response(render_template('index.html', user=user))
    # Prevent caching
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('index'))
        
        return render_template('login.html', error='Invalid credentials')
    
    response = make_response(render_template('login.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        user_id = create_user(username, password)
        if user_id:
            session['user_id'] = user_id
            return redirect(url_for('index'))
        
        return render_template('register.html', error='Username already exists')
    
    response = make_response(render_template('register.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response
@app.route('/check_auth')
def check_auth():
    return jsonify({'authenticated': 'user_id' in session})

# Google OAuth routes
@app.route('/login/google')
def login_google():
    return google.authorize_redirect(url_for('authorized', _external=True))

@app.route('/login/google/authorized')
def authorized():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token)
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (user_info['email'],))
    user = c.fetchone()
    
    if not user:
        random_password = str(uuid.uuid4())
        # Correct: Keep salt as bytes
        hashed_password = bcrypt.hashpw(random_password.encode('utf-8'), bcrypt.gensalt())
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                 (user_info['email'], hashed_password.decode('utf-8')))
    else:
        user_id = user[0]
    
    session['user_id'] = user_id
    conn.close()
    return redirect(url_for('index'))

# Playlist management functions
def save_playlist(user_id, name, songs):
    playlist_id = str(uuid.uuid4())
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO playlists (id, user_id, name, songs, created_at) VALUES (?, ?, ?, ?, ?)',
             (playlist_id, user_id, name, json.dumps(songs), datetime.now()))
    conn.commit()
    conn.close()
    return playlist_id

def get_user_playlists(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM playlists WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
    playlists = [{
        'id': row[0],
        'name': row[2],
        'songs': json.loads(row[3]),
        'created_at': row[4]
    } for row in c.fetchall()]
    conn.close()
    return playlists

def rename_playlist(playlist_id, new_name):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('UPDATE playlists SET name = ? WHERE id = ?', (new_name, playlist_id))
    conn.commit()
    conn.close()
    return c.rowcount > 0

def delete_playlist(playlist_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM playlists WHERE id = ?', (playlist_id,))
    conn.commit()
    conn.close()
    return c.rowcount > 0

# Spotify API functions
def get_spotify_token():
    auth_header = base64.b64encode(f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}".encode()).decode()
    headers = {'Authorization': f'Basic {auth_header}'}
    data = {'grant_type': 'client_credentials'}
    response = requests.post('https://accounts.spotify.com/api/token', headers=headers, data=data)
    return response.json().get('access_token') if response.ok else None

def search_tracks(genre):
    access_token = get_spotify_token()
    if not access_token:
        return []
    
    params = {
        'q': f'genre:{genre}',
        'type': 'track',
        'limit': 10,
        'market': 'IN',
        'offset': random.randint(0, 90)  # Randomize search results offset
    }
    
    response = requests.get(
        'https://api.spotify.com/v1/search',
        headers={'Authorization': f'Bearer {access_token}'},
        params=params
    )
    
    if not response.ok:
        return []
    
    tracks = response.json().get('tracks', {}).get('items', [])
    
    # Shuffle the results server-side before returning
    random.shuffle(tracks)
    
    return [{
        'name': track['name'],
        'artist': track['artists'][0]['name'],
        'url': track['external_urls']['spotify']
    } for track in tracks]

# Application routes
@app.route('/get_songs')
def get_songs():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    genre = request.args.get('genre', 'bollywood')
    return jsonify({'tracks': search_tracks(genre)})

@app.route('/save_playlist', methods=['POST'])
def save_playlist_route():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    playlist_id = save_playlist(session['user_id'], data['name'], data['songs'])
    return jsonify({'id': playlist_id, 'name': data['name']})

@app.route('/get_saved_playlists')
def get_saved_playlists():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    return jsonify(get_user_playlists(session['user_id']))

@app.route('/rename_playlist', methods=['POST'])
def rename_playlist_route():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    if rename_playlist(data['id'], data['new_name']):
        return jsonify({'success': True})
    return jsonify({'error': 'Playlist not found'}), 404

@app.route('/delete_playlist/<playlist_id>', methods=['DELETE'])
def delete_playlist_route(playlist_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if delete_playlist(playlist_id):
        return jsonify({'success': True})
    return jsonify({'error': 'Playlist not found'}), 404

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80,debug=True)
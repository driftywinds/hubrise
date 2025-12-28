from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets
import threading
import time
import requests
import json
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Configuration
# Support environment variable for database path
db_path = os.getenv('DATABASE_PATH', 'sqlite:///github_monitor.db')
if not db_path.startswith('sqlite:///'):
    db_path = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_DATABASE_URI'] = db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Shared Telegram Bot Configuration
app.config['TELEGRAM_BOT_TOKEN'] = os.getenv('TELEGRAM_BOT_TOKEN')

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    repositories = db.relationship('Repository', backref='user', lazy=True, cascade='all, delete-orphan')
    apprise_endpoints = db.relationship('AppriseEndpoint', backref='user', lazy=True, cascade='all, delete-orphan')

class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    repo_url = db.Column(db.String(500), nullable=False)
    repo_owner = db.Column(db.String(200), nullable=False)
    repo_name = db.Column(db.String(200), nullable=False)
    latest_release = db.Column(db.String(100))
    latest_release_url = db.Column(db.String(500))
    latest_release_body = db.Column(db.Text)
    last_checked = db.Column(db.DateTime)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

class AppriseEndpoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    endpoint = db.Column(db.String(500), nullable=False)
    name = db.Column(db.String(100))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(500))

class GitHubToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(200), nullable=False)
    last_used = db.Column(db.DateTime)
    rate_limit_remaining = db.Column(db.Integer, default=60)
    rate_limit_reset = db.Column(db.DateTime)

# GitHub API Handler
class GitHubAPI:
    def __init__(self):
        self.current_token_index = 0
    
    def get_token(self):
        tokens = GitHubToken.query.all()
        if not tokens:
            return None
        
        # Find token with available rate limit
        now = datetime.utcnow()
        for i in range(len(tokens)):
            idx = (self.current_token_index + i) % len(tokens)
            token = tokens[idx]
            
            if token.rate_limit_remaining > 0 or (token.rate_limit_reset and token.rate_limit_reset < now):
                self.current_token_index = idx
                return token.token
        
        return None
    
    def get_latest_release(self, owner, repo):
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
        headers = {}
        
        token = self.get_token()
        if token:
            headers['Authorization'] = f'token {token}'
        
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            
            # Update rate limit info
            if token:
                remaining = resp.headers.get('X-RateLimit-Remaining')
                reset = resp.headers.get('X-RateLimit-Reset')
                if remaining:
                    token_obj = GitHubToken.query.filter_by(token=token).first()
                    if token_obj:
                        token_obj.rate_limit_remaining = int(remaining)
                        if reset:
                            token_obj.rate_limit_reset = datetime.fromtimestamp(int(reset))
                        db.session.commit()
            
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'tag_name': data.get('tag_name'),
                    'html_url': data.get('html_url'),
                    'name': data.get('name'),
                    'body': data.get('body', '')[:500],  # First 500 chars of release notes
                    'published_at': data.get('published_at')
                }
            elif resp.status_code == 404:
                # No releases found
                return None
            return None
        except requests.exceptions.Timeout:
            print(f"Timeout fetching release for {owner}/{repo} - will retry next cycle")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Network error fetching release for {owner}/{repo}: {e}")
            return None
        except Exception as e:
            print(f"Error fetching release for {owner}/{repo}: {e}")
            return None

github_api = GitHubAPI()

# Monitoring Thread
class MonitoringService:
    def __init__(self):
        self.running = False
        self.thread = None
    
    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
    
    def stop(self):
        self.running = False
    
    def _monitor_loop(self):
        while self.running:
            try:
                with app.app_context():
                    self._check_repositories()
                    
                    # Get polling interval (in minutes) - inside app context
                    config = Config.query.filter_by(key='polling_interval').first()
                    interval = int(config.value) if config else 60
            except Exception as e:
                print(f"Monitor error: {e}")
                interval = 60  # Default interval on error
            
            time.sleep(interval * 60)
    
    def _check_repositories(self):
        repos = Repository.query.all()
        
        for repo in repos:
            try:
                latest = github_api.get_latest_release(repo.repo_owner, repo.repo_name)
                
                if latest and latest['tag_name'] != repo.latest_release:
                    # New release detected
                    old_release = repo.latest_release
                    repo.latest_release = latest['tag_name']
                    repo.latest_release_url = latest['html_url']
                    repo.latest_release_body = latest.get('body', '')
                    repo.last_checked = datetime.utcnow()
                    db.session.commit()
                    
                    # Send notifications (only if there was a previous release)
                    if old_release:
                        self._send_notifications(repo, latest)
                else:
                    repo.last_checked = datetime.utcnow()
                    db.session.commit()
                
                time.sleep(1)  # Rate limiting between repos
            except Exception as e:
                print(f"Error checking {repo.repo_owner}/{repo.repo_name}: {e}")
    
    def _resolve_endpoint(self, endpoint_str):
        """
        Resolves internal protocol schemas to actual Apprise URLs.
        Handles 'telegram-shared://chat_id' -> 'tgram://token/chat_id'
        """
        if endpoint_str.startswith('telegram-shared://'):
            chat_id = endpoint_str.split('telegram-shared://')[1]
            token = app.config.get('TELEGRAM_BOT_TOKEN')
            if token:
                # Construct the real Telegram URL
                # tgram://{bot_token}/{chat_id}
                return f"tgram://{token}/{chat_id}"
            else:
                print(f"Error: Shared Telegram Bot Token not configured in environment.")
                return None
        return endpoint_str

    def _send_notifications(self, repo, release_info):
        user = db.session.get(User, repo.user_id)
        endpoints = AppriseEndpoint.query.filter_by(user_id=user.id).all()
    
        title = f"New Release: {repo.repo_owner}/{repo.repo_name}"
    
        # Build the body with release notes in code block
        body_parts = [f"Version {release_info['tag_name']} has been released!"]
    
        if release_info.get('name'):
            body_parts.append(f"Release Name: {release_info['name']}")
    
        # Add release notes in code block if available
        release_body = release_info.get('body', '').strip()
        if release_body:
            # Limit to 800 characters to keep notifications reasonable
            max_chars = 800
            if len(release_body) > max_chars:
                release_body = release_body[:max_chars] + "..."
        
            # Escape backticks to prevent code block injection
            # Replace ` with ′ (prime symbol) or remove them
            release_body = release_body.replace('`', '′')
        
            # Also escape any other potentially problematic characters
            # Remove or replace null bytes and other control characters
            release_body = ''.join(char if ord(char) >= 32 or char in '\n\r\t' else '' for char in release_body)
        
            body_parts.append(f"\nRelease Notes:\n```\n{release_body}\n```")
    
        body_parts.append(f"\nView Release: {release_info['html_url']}")
    
        body = '\n'.join(body_parts)
    
        for endpoint in endpoints:
            try:
                # Resolve the actual URL (handles shared bot logic)
                real_url = self._resolve_endpoint(endpoint.endpoint)
            
                if real_url:
                    self._send_apprise_notification(real_url, title, body)
                    print(f"Notification sent to {user.username} via {endpoint.name}")
                else:
                    print(f"Skipping notification for {user.username}: Endpoint resolution failed ({endpoint.name})")
                
            except Exception as e:
                print(f"Error sending notification to {endpoint.name}: {e}")

    def _send_apprise_notification(self, endpoint, title, body):
        try:
            import apprise
            apobj = apprise.Apprise()
            apobj.add(endpoint)
            apobj.notify(title=title, body=body)
        except ImportError:
            # Fallback if apprise not installed
            print(f"Apprise not installed. Would send: {title} - {body}")
        except Exception as e:
            raise Exception(f"Failed to send notification: {str(e)}")

monitor_service = MonitoringService()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        user = db.session.get(User, session['user_id'])
        if not user or not user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    # Check if registrations are disabled
    with app.app_context():
        reg_config = Config.query.filter_by(key='registrations_enabled').first()
        if reg_config and reg_config.value == 'false':
            return jsonify({'error': 'Registrations are disabled. Contact an administrator.'}), 403
    
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    # First user is admin
    is_admin = User.query.count() == 0
    
    user = User(
        username=username,
        password=generate_password_hash(password),
        is_admin=is_admin
    )
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully', 'is_admin': is_admin}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        return jsonify({
            'message': 'Login successful',
            'username': user.username,
            'is_admin': user.is_admin
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/user', methods=['GET'])
@login_required
def get_user():
    user = db.session.get(User, session['user_id'])
    
    # Check if shared telegram bot is configured on server
    telegram_configured = bool(app.config.get('TELEGRAM_BOT_TOKEN'))
    
    return jsonify({
        'username': user.username,
        'is_admin': user.is_admin,
        'telegram_bot_configured': telegram_configured
    })

@app.route('/api/repositories', methods=['GET', 'POST'])
@login_required
def repositories():
    if request.method == 'GET':
        repos = Repository.query.filter_by(user_id=session['user_id']).all()
        return jsonify([{
            'id': r.id,
            'repo_url': r.repo_url,
            'repo_owner': r.repo_owner,
            'repo_name': r.repo_name,
            'latest_release': r.latest_release,
            'latest_release_url': r.latest_release_url,
            'latest_release_body': r.latest_release_body,
            'last_checked': r.last_checked.isoformat() if r.last_checked else None,
            'added_at': r.added_at.isoformat()
        } for r in repos])
    
    elif request.method == 'POST':
        data = request.json
        repo_url = data.get('repo_url', '').strip()
        
        # Parse GitHub URL
        if 'github.com/' in repo_url:
            parts = repo_url.split('github.com/')[-1].strip('/').split('/')
            if len(parts) >= 2:
                owner, name = parts[0], parts[1]
            else:
                return jsonify({'error': 'Invalid GitHub URL'}), 400
        else:
            return jsonify({'error': 'Invalid GitHub URL'}), 400
        
        # Check if already exists
        existing = Repository.query.filter_by(
            user_id=session['user_id'],
            repo_owner=owner,
            repo_name=name
        ).first()
        
        if existing:
            return jsonify({'error': 'Repository already added'}), 400
        
        # Fetch initial release info
        latest = github_api.get_latest_release(owner, name)
        
        repo = Repository(
            user_id=session['user_id'],
            repo_url=f"https://github.com/{owner}/{name}",
            repo_owner=owner,
            repo_name=name,
            latest_release=latest['tag_name'] if latest else None,
            latest_release_url=latest['html_url'] if latest else None,
            latest_release_body=latest.get('body', '') if latest else None,
            last_checked=datetime.utcnow()
        )
        db.session.add(repo)
        db.session.commit()
        
        return jsonify({'message': 'Repository added', 'id': repo.id}), 201

@app.route('/api/repositories/<int:repo_id>', methods=['DELETE'])
@login_required
def delete_repository(repo_id):
    repo = Repository.query.filter_by(id=repo_id, user_id=session['user_id']).first()
    if not repo:
        return jsonify({'error': 'Repository not found'}), 404
    
    db.session.delete(repo)
    db.session.commit()
    return jsonify({'message': 'Repository deleted'})

@app.route('/api/apprise-endpoints', methods=['GET', 'POST'])
@login_required
def apprise_endpoints():
    if request.method == 'GET':
        endpoints = AppriseEndpoint.query.filter_by(user_id=session['user_id']).all()
        return jsonify([{
            'id': e.id,
            'endpoint': e.endpoint,
            'name': e.name,
            'added_at': e.added_at.isoformat()
        } for e in endpoints])
    
    elif request.method == 'POST':
        data = request.json
        endpoint = data.get('endpoint', '').strip()
        name = data.get('name', '').strip()
        
        if not endpoint:
            return jsonify({'error': 'Endpoint required'}), 400
        
        apprise_ep = AppriseEndpoint(
            user_id=session['user_id'],
            endpoint=endpoint,
            name=name or endpoint
        )
        db.session.add(apprise_ep)
        db.session.commit()
        
        return jsonify({'message': 'Endpoint added', 'id': apprise_ep.id}), 201

@app.route('/api/apprise-endpoints/<int:endpoint_id>', methods=['DELETE'])
@login_required
def delete_apprise_endpoint(endpoint_id):
    endpoint = AppriseEndpoint.query.filter_by(id=endpoint_id, user_id=session['user_id']).first()
    if not endpoint:
        return jsonify({'error': 'Endpoint not found'}), 404
    
    db.session.delete(endpoint)
    db.session.commit()
    return jsonify({'message': 'Endpoint deleted'})

@app.route('/api/apprise-endpoints/<int:endpoint_id>/test', methods=['POST'])
@login_required
def test_apprise_endpoint(endpoint_id):
    endpoint = AppriseEndpoint.query.filter_by(id=endpoint_id, user_id=session['user_id']).first()
    if not endpoint:
        return jsonify({'error': 'Endpoint not found'}), 404
    
    try:
        # Resolve shared bot URL if needed
        real_url = monitor_service._resolve_endpoint(endpoint.endpoint)
        if not real_url:
            return jsonify({'error': 'Failed to resolve endpoint. If this is a shared Telegram bot, contact admin.'}), 400

        import apprise
        apobj = apprise.Apprise()
        apobj.add(real_url)
        success = apobj.notify(
            title="Test Notification - GitHub Release Monitor",
            body="This is a test notification. If you received this, your Apprise endpoint is configured correctly!"
        )
        if success:
            return jsonify({'message': 'Test notification sent successfully!'})
        else:
            return jsonify({'error': 'Failed to send test notification. Check your endpoint configuration.'}), 400
    except ImportError:
        return jsonify({'error': 'Apprise library not installed on server'}), 500
    except Exception as e:
        return jsonify({'error': f'Error sending notification: {str(e)}'}), 400

@app.route('/api/admin/config', methods=['GET', 'POST'])
@admin_required
def admin_config():
    if request.method == 'GET':
        interval = Config.query.filter_by(key='polling_interval').first()
        reg_enabled = Config.query.filter_by(key='registrations_enabled').first()
        tokens = GitHubToken.query.all()
        
        return jsonify({
            'polling_interval': int(interval.value) if interval else 60,
            'registrations_enabled': reg_enabled.value == 'true' if reg_enabled else True,
            'tokens': [{
                'id': t.id,
                'token': t.token[:8] + '...',
                'rate_limit_remaining': t.rate_limit_remaining,
                'rate_limit_reset': t.rate_limit_reset.isoformat() if t.rate_limit_reset else None
            } for t in tokens]
        })
    
    elif request.method == 'POST':
        data = request.json
        
        if 'polling_interval' in data:
            interval = int(data['polling_interval'])
            if interval < 1:
                return jsonify({'error': 'Interval must be at least 1 minute'}), 400
            
            config = Config.query.filter_by(key='polling_interval').first()
            if config:
                config.value = str(interval)
            else:
                config = Config(key='polling_interval', value=str(interval))
                db.session.add(config)
            db.session.commit()
        
        if 'registrations_enabled' in data:
            enabled = 'true' if data['registrations_enabled'] else 'false'
            config = Config.query.filter_by(key='registrations_enabled').first()
            if config:
                config.value = enabled
            else:
                config = Config(key='registrations_enabled', value=enabled)
                db.session.add(config)
            db.session.commit()
        
        return jsonify({'message': 'Config updated'})

@app.route('/api/admin/tokens', methods=['POST', 'DELETE'])
@admin_required
def admin_tokens():
    if request.method == 'POST':
        data = request.json
        token = data.get('token', '').strip()
        
        if not token:
            return jsonify({'error': 'Token required'}), 400
        
        github_token = GitHubToken(token=token)
        db.session.add(github_token)
        db.session.commit()
        
        return jsonify({'message': 'Token added', 'id': github_token.id}), 201
    
    elif request.method == 'DELETE':
        token_id = request.json.get('id')
        token = db.session.get(GitHubToken, token_id)
        if token:
            db.session.delete(token)
            db.session.commit()
        return jsonify({'message': 'Token deleted'})

@app.route('/api/admin/poll-now', methods=['POST'])
@admin_required
def poll_now():
    """Trigger an immediate poll of all repositories"""
    try:
        with app.app_context():
            monitor_service._check_repositories()
        return jsonify({'message': 'Poll completed successfully'})
    except Exception as e:
        return jsonify({'error': f'Poll failed: {str(e)}'}), 500

@app.route('/api/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    if request.method == 'GET':
        users = User.query.all()
        return jsonify([{
            'id': u.id,
            'username': u.username,
            'is_admin': u.is_admin,
            'created_at': u.created_at.isoformat(),
            'repo_count': len(u.repositories),
            'endpoint_count': len(u.apprise_endpoints)
        } for u in users])
    
    elif request.method == 'POST':
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        is_admin = data.get('is_admin', False)
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        user = User(
            username=username,
            password=generate_password_hash(password),
            is_admin=is_admin
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'message': 'User created', 'id': user.id}), 201

@app.route('/api/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_user_manage(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if request.method == 'PUT':
        data = request.json
        
        # Prevent removing the last admin
        if 'is_admin' in data and not data['is_admin']:
            admin_count = User.query.filter_by(is_admin=True).count()
            if admin_count == 1 and user.is_admin:
                return jsonify({'error': 'Cannot remove the last admin'}), 400
        
        if 'is_admin' in data:
            user.is_admin = data['is_admin']
        
        if 'password' in data and data['password']:
            user.password = generate_password_hash(data['password'])
        
        db.session.commit()
        return jsonify({'message': 'User updated'})
    
    elif request.method == 'DELETE':
        # Prevent deleting yourself
        if user.id == session['user_id']:
            return jsonify({'error': 'Cannot delete your own account'}), 400
        
        # Prevent deleting the last admin
        if user.is_admin:
            admin_count = User.query.filter_by(is_admin=True).count()
            if admin_count == 1:
                return jsonify({'error': 'Cannot delete the last admin'}), 400
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted'})

@app.route('/api/config/registrations-enabled', methods=['GET'])
def get_registrations_enabled():
    """Public endpoint to check if registrations are enabled"""
    config = Config.query.filter_by(key='registrations_enabled').first()
    enabled = config.value == 'true' if config else True
    return jsonify({'enabled': enabled})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Migrate existing database - add latest_release_body column if it doesn't exist
        try:
            from sqlalchemy import text
            with db.engine.connect() as conn:
                # Check if column exists
                result = conn.execute(text("PRAGMA table_info(repository)")).fetchall()
                columns = [row[1] for row in result]
                
                if 'latest_release_body' not in columns:
                    print("Migrating database: Adding latest_release_body column...")
                    conn.execute(text("ALTER TABLE repository ADD COLUMN latest_release_body TEXT"))
                    conn.commit()
                    print("Migration complete!")
        except Exception as e:
            print(f"Migration check: {e}")
        
        # Set default polling interval
        if not Config.query.filter_by(key='polling_interval').first():
            db.session.add(Config(key='polling_interval', value='60'))
        # Set default registrations enabled
        if not Config.query.filter_by(key='registrations_enabled').first():
            db.session.add(Config(key='registrations_enabled', value='true'))
        db.session.commit()
    
    monitor_service.start()
    print("Starting GitHub Release Monitor...")
    print("Access the web interface at: http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
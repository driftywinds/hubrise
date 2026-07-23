from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import secrets
import threading
import time
import requests
import json
import os
import urllib.parse
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
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    repositories = db.relationship('Repository', backref='user', lazy=True, cascade='all, delete-orphan')
    apprise_endpoints = db.relationship('AppriseEndpoint', backref='user', lazy=True, cascade='all, delete-orphan')

class Repository(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    repo_url = db.Column(db.String(500), nullable=False)
    repo_owner = db.Column(db.String(200), nullable=False)
    repo_name = db.Column(db.String(200), nullable=False)
    platform = db.Column(db.String(20), default='github')
    instance_url = db.Column(db.String(500))
    latest_release = db.Column(db.String(100))
    latest_release_url = db.Column(db.String(500))
    latest_release_body = db.Column(db.Text)
    notify_pre_releases = db.Column(db.Boolean, default=False)
    last_checked = db.Column(db.DateTime)
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class AppriseEndpoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    endpoint = db.Column(db.String(500), nullable=False)
    name = db.Column(db.String(100))
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(500))

class PlatformToken(db.Model):
    __tablename__ = 'github_token'
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(20), nullable=False, default='github')
    token = db.Column(db.String(500), nullable=False)
    label = db.Column(db.String(100))
    instance_url = db.Column(db.String(500))
    last_used = db.Column(db.DateTime)
    rate_limit_remaining = db.Column(db.Integer, default=60)
    rate_limit_reset = db.Column(db.DateTime)

# GitHub API Handler
class GitHubAPI:
    def __init__(self):
        self.current_token_index = 0
    
    def get_token(self):
        tokens = PlatformToken.query.filter_by(platform='github').all()
        if not tokens:
            return None
        
        # Find token with available rate limit
        now = datetime.now(timezone.utc)
        for i in range(len(tokens)):
            idx = (self.current_token_index + i) % len(tokens)
            token = tokens[idx]
            
            if token.rate_limit_remaining > 0 or (token.rate_limit_reset and token.rate_limit_reset < now):
                self.current_token_index = idx
                return token.token
        
        return None
    
    def get_latest_release(self, owner, repo, include_prereleases=False):
        if include_prereleases:
            return self._get_latest_release_with_prereleases(owner, repo)
        
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
        headers = {}
        
        token = self.get_token()
        if token:
            headers['Authorization'] = f'token {token}'
        
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            
            # Update rate limit info
            self._update_rate_limit(token, resp)
            
            if resp.status_code == 200:
                data = resp.json()
                return {
                    'tag_name': data.get('tag_name'),
                    'html_url': data.get('html_url'),
                    'name': data.get('name'),
                    'body': data.get('body', '')[:2000],
                    'published_at': data.get('published_at'),
                    'prerelease': data.get('prerelease', False)
                }
            elif resp.status_code == 404:
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
    
    def _get_latest_release_with_prereleases(self, owner, repo):
        """Fetch latest release including pre-releases by listing all releases."""
        url = f"https://api.github.com/repos/{owner}/{repo}/releases?per_page=10"
        headers = {}
        
        token = self.get_token()
        if token:
            headers['Authorization'] = f'token {token}'
        
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            self._update_rate_limit(token, resp)
            
            if resp.status_code == 200:
                releases = resp.json()
                if releases:
                    # Return the most recent release (first in list)
                    data = releases[0]
                    return {
                        'tag_name': data.get('tag_name'),
                        'html_url': data.get('html_url'),
                        'name': data.get('name'),
                        'body': data.get('body', '')[:2000],
                        'published_at': data.get('published_at'),
                        'prerelease': data.get('prerelease', False)
                    }
            return None
        except requests.exceptions.Timeout:
            print(f"Timeout fetching releases for {owner}/{repo} - will retry next cycle")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Network error fetching releases for {owner}/{repo}: {e}")
            return None
        except Exception as e:
            print(f"Error fetching releases for {owner}/{repo}: {e}")
            return None
    
    def _update_rate_limit(self, token, resp):
        """Update rate limit info for the given token."""
        if token:
            remaining = resp.headers.get('X-RateLimit-Remaining')
            reset = resp.headers.get('X-RateLimit-Reset')
            if remaining:
                token_obj = PlatformToken.query.filter_by(token=token).first()
                if token_obj:
                    token_obj.rate_limit_remaining = int(remaining)
                    if reset:
                        token_obj.rate_limit_reset = datetime.fromtimestamp(int(reset), tz=timezone.utc)
                    db.session.commit()

    def test_token(self, token):
        """Test if a GitHub token is valid by making a simple API call."""
        url = "https://api.github.com/rate_limit"
        headers = {'Authorization': f'token {token}'}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            return resp.status_code == 200
        except:
            return False

github_api = GitHubAPI()


class GitLabAPI:
    """Handler for GitLab Releases API (supports gitlab.com and self-hosted instances)."""

    def __init__(self):
        self.current_token_index = 0

    def get_token(self):
        tokens = PlatformToken.query.filter_by(platform='gitlab').all()
        if not tokens:
            return None

        now = datetime.now(timezone.utc)
        for i in range(len(tokens)):
            idx = (self.current_token_index + i) % len(tokens)
            token = tokens[idx]

            if token.rate_limit_remaining > 0 or (token.rate_limit_reset and token.rate_limit_reset < now):
                self.current_token_index = idx
                return token.token

        return None

    def _build_base_url(self, instance_url=None):
        if instance_url:
            return f"https://{instance_url}"
        return "https://gitlab.com"

    def _build_release_html_url(self, project_path, tag_name, instance_url=None):
        base = self._build_base_url(instance_url)
        return f"{base}/{project_path}/-/releases/{tag_name}"

    def _update_rate_limit(self, token, resp):
        if token:
            remaining = resp.headers.get('RateLimit-Remaining')
            reset = resp.headers.get('RateLimit-Reset')
            if remaining:
                token_obj = PlatformToken.query.filter_by(token=token).first()
                if token_obj:
                    token_obj.rate_limit_remaining = int(remaining)
                    if reset:
                        try:
                            token_obj.rate_limit_reset = datetime.fromtimestamp(int(reset), tz=timezone.utc)
                        except (ValueError, OSError):
                            pass
                    db.session.commit()

    def _fetch_releases(self, url, headers):
        """Make the API request and process the response into release data.
        Returns (release_dict, used_token) on success, or None on failure."""
        resp = requests.get(url, headers=headers, timeout=30)
        used_token = headers.get('PRIVATE-TOKEN')
        self._update_rate_limit(used_token, resp)

        if resp.status_code != 200:
            return None

        releases = resp.json()
        if not releases:
            return None
        return releases

    def _process_releases(self, releases, project_path, include_prereleases, instance_url):
        """Process a list of releases and extract the latest one."""
        if not releases:
            return None

        if include_prereleases:
            data = releases[0]
        else:
            data = None
            for release in releases:
                if not release.get('prerelease', False):
                    data = release
                    break
            if not data:
                data = releases[0]

        tag_name = data.get('tag_name', '')
        return {
            'tag_name': tag_name,
            'html_url': self._build_release_html_url(project_path, tag_name, instance_url),
            'name': data.get('name'),
            'body': (data.get('description') or '')[:2000],
            'published_at': data.get('released_at'),
            'prerelease': data.get('prerelease', False)
        }

    def get_latest_release(self, project_path, include_prereleases=False, instance_url=None):
        """
        Fetch the latest release for a GitLab project.
        Falls back to unauthenticated request if token is invalid.
        
        Args:
            project_path: URL-encoded project path (e.g., 'owner/project' or 'group/subgroup/project')
            include_prereleases: If True, include pre-releases in the latest check
            instance_url: For self-hosted GitLab instances (e.g., 'gitlab.example.com')
        """
        base_url = self._build_base_url(instance_url)
        encoded_path = urllib.parse.quote(project_path, safe='')

        # GitLab doesn't have a dedicated "latest non-prerelease" endpoint.
        # We always fetch the recent releases list and filter if needed.
        url = f"{base_url}/api/v4/projects/{encoded_path}/releases?per_page=20"

        releases = None
        token = self.get_token()

        try:
            # Try with token first (may return None if token is invalid/expired)
            if token:
                releases = self._fetch_releases(url, {'PRIVATE-TOKEN': token})

            # If token-based request failed or no token, try without auth (public repos)
            if releases is None:
                releases = self._fetch_releases(url, {})
        except requests.exceptions.Timeout:
            print(f"Timeout fetching release for {project_path} - will retry next cycle")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Network error fetching release for {project_path}: {e}")
            return None
        except Exception as e:
            print(f"Error fetching release for {project_path}: {e}")
            return None

        if releases is None:
            return None

        return self._process_releases(releases, project_path, include_prereleases, instance_url)

    def test_token(self, token, instance_url=None):
        """Test if a GitLab token is valid by making a simple API call."""
        base_url = self._build_base_url(instance_url)
        url = f"{base_url}/api/v4/user"
        headers = {'PRIVATE-TOKEN': token}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            return resp.status_code == 200
        except:
            return False


gitlab_api = GitLabAPI()


# Supported Gitea-compatible platforms and their known instances
GITEA_COMPATIBLE_PLATFORMS = ('codeberg', 'gitea', 'forgejo')
GITEA_KNOWN_INSTANCES = {
    'codeberg': 'codeberg.org',
    'gitea': 'demo.gitea.com',
    'forgejo': None,  # Forgejo is self-hosted only
}


class GiteaCompatibleAPI:
    """Handler for Gitea-compatible Releases API (Codeberg, Gitea, Forgejo).
    All three share the same API structure at /api/v1/.
    Supports self-hosted instances."""

    def __init__(self):
        self.current_token_index = 0

    def get_token(self, platform, instance_url=None):
        """Get a token for the specific Gitea-compatible platform and instance."""
        if instance_url:
            tokens = PlatformToken.query.filter_by(platform=platform, instance_url=instance_url).all()
            if not tokens:
                tokens = PlatformToken.query.filter_by(platform=platform, instance_url=None).all()
        else:
            tokens = PlatformToken.query.filter_by(platform=platform).all()
        if not tokens:
            return None

        now = datetime.now(timezone.utc)
        for i in range(len(tokens)):
            idx = (self.current_token_index + i) % len(tokens)
            token = tokens[idx]

            if token.rate_limit_remaining > 0 or (token.rate_limit_reset and token.rate_limit_reset < now):
                self.current_token_index = idx
                return token.token

        return None

    def _build_base_url(self, platform, instance_url=None):
        """Build the base URL for the platform."""
        if instance_url:
            return f"https://{instance_url}"
        known = GITEA_KNOWN_INSTANCES.get(platform)
        if known:
            return f"https://{known}"
        raise ValueError(f"No instance URL provided for platform '{platform}'")

    def _build_release_html_url(self, owner, repo, tag_name, base_url):
        """Build the HTML URL for a release."""
        return f"{base_url}/{owner}/{repo}/releases/tag/{tag_name}"

    def _update_rate_limit(self, token, resp):
        """Update rate limit info for the given token."""
        if token:
            remaining = resp.headers.get('X-RateLimit-Remaining')
            reset = resp.headers.get('X-RateLimit-Reset')
            if remaining:
                token_obj = PlatformToken.query.filter_by(token=token).first()
                if token_obj:
                    token_obj.rate_limit_remaining = int(remaining)
                    if reset:
                        try:
                            token_obj.rate_limit_reset = datetime.fromtimestamp(int(reset), tz=timezone.utc)
                        except (ValueError, OSError):
                            pass
                    db.session.commit()

    def _fetch_releases(self, url, headers):
        """Fetch releases from the API. Returns list of releases or None."""
        resp = requests.get(url, headers=headers, timeout=30)
        token = headers.get('Authorization', '').replace('token ', '')
        self._update_rate_limit(token, resp)

        if resp.status_code != 200:
            return None

        releases = resp.json()
        return releases if releases else None

    def _process_releases(self, releases, owner, repo, include_prereleases, base_url):
        """Process a list of releases and extract the latest one."""
        if not releases:
            return None

        if include_prereleases:
            data = releases[0]
        else:
            data = None
            for release in releases:
                if not release.get('prerelease', False):
                    data = release
                    break
            if not data:
                data = releases[0]

        tag_name = data.get('tag_name', '')
        return {
            'tag_name': tag_name,
            'html_url': self._build_release_html_url(owner, repo, tag_name, base_url),
            'name': data.get('name'),
            'body': (data.get('body') or '')[:2000],
            'published_at': data.get('created_at') or data.get('published_at'),
            'prerelease': data.get('prerelease', False)
        }

    def get_latest_release(self, owner, repo, include_prereleases=False, platform='gitea', instance_url=None):
        """
        Fetch the latest release for a Gitea-compatible repository.

        Args:
            owner: Repository owner (e.g., 'driftywinds')
            repo: Repository name (e.g., 'hubrise')
            include_prereleases: If True, include pre-releases
            platform: One of 'codeberg', 'gitea', 'forgejo'
            instance_url: For self-hosted instances (e.g., 'gitea.example.com')
        """
        base_url = self._build_base_url(platform, instance_url)
        url = f"{base_url}/api/v1/repos/{owner}/{repo}/releases?limit=20"

        releases = None
        token = self.get_token(platform, instance_url)

        try:
            # Try with token first
            if token:
                releases = self._fetch_releases(url, {'Authorization': f'token {token}'})

            # If token-based request failed or no token, try without auth (public repos)
            if releases is None:
                releases = self._fetch_releases(url, {})
        except requests.exceptions.Timeout:
            print(f"Timeout fetching release for {owner}/{repo} on {platform} - will retry next cycle")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Network error fetching release for {owner}/{repo} on {platform}: {e}")
            return None
        except Exception as e:
            print(f"Error fetching release for {owner}/{repo} on {platform}: {e}")
            return None

        if releases is None:
            return None

        return self._process_releases(releases, owner, repo, include_prereleases, base_url)

    def test_token(self, token, platform='gitea', instance_url=None):
        """Test if a token is valid by making a simple API call."""
        base_url = self._build_base_url(platform, instance_url)
        url = f"{base_url}/api/v1/user"
        headers = {'Authorization': f'token {token}'}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            return resp.status_code == 200
        except:
            return False


gitea_api = GiteaCompatibleAPI()


def get_api_handler(platform):
    """Return the appropriate API handler for the given platform."""
    if platform == 'github':
        return github_api
    elif platform == 'gitlab':
        return gitlab_api
    elif platform in GITEA_COMPATIBLE_PLATFORMS:
        return gitea_api
    else:
        raise ValueError(f"Unsupported platform: {platform}")


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
                api_handler = get_api_handler(repo.platform)

                if repo.platform == 'github':
                    latest = api_handler.get_latest_release(
                        repo.repo_owner, repo.repo_name,
                        include_prereleases=repo.notify_pre_releases
                    )
                elif repo.platform == 'gitlab':
                    latest = api_handler.get_latest_release(
                        repo.repo_owner,
                        include_prereleases=repo.notify_pre_releases,
                        instance_url=repo.instance_url
                    )
                elif repo.platform in GITEA_COMPATIBLE_PLATFORMS:
                    latest = api_handler.get_latest_release(
                        repo.repo_owner, repo.repo_name,
                        include_prereleases=repo.notify_pre_releases,
                        platform=repo.platform,
                        instance_url=repo.instance_url
                    )
                else:
                    print(f"Unknown platform '{repo.platform}' for repo {repo.id}")
                    continue

                if latest:
                    # Check if this is a new/different release
                    if latest['tag_name'] != repo.latest_release:
                        # New release detected
                        old_release = repo.latest_release
                        repo.latest_release = latest['tag_name']
                        repo.latest_release_url = latest['html_url']
                        repo.latest_release_body = latest.get('body', '')
                        repo.last_checked = datetime.now(timezone.utc)
                        db.session.commit()

                        # Send notifications (only if there was a previous release)
                        if old_release:
                            self._send_notifications(repo, latest)
                    else:
                        # Same release tag — always refresh body/URL to ensure
                        # data is current (covers case where initial fetch stored
                        # the tag but body was empty, or body was truncated)
                        latest_body = latest.get('body', '')
                        latest_url = latest.get('html_url')
                        if latest_body and latest_body != repo.latest_release_body:
                            repo.latest_release_body = latest_body
                        if latest_url and latest_url != repo.latest_release_url:
                            repo.latest_release_url = latest_url
                        repo.last_checked = datetime.now(timezone.utc)
                        db.session.commit()
                else:
                    repo.last_checked = datetime.now(timezone.utc)
                    db.session.commit()

                time.sleep(1)  # Rate limiting between repos
            except Exception as e:
                display_name = repo.repo_owner if repo.platform == 'gitlab' else f"{repo.repo_owner}/{repo.repo_name}"
                print(f"Error checking {display_name}: {e}")
    
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
    
        # Build display name based on platform
        if repo.platform == 'gitlab':
            display_name = repo.repo_owner
        else:
            display_name = f"{repo.repo_owner}/{repo.repo_name}"
        title = f"New Release: {display_name}"
    
        # Get release notes
        release_body = release_info.get('body', '').strip()
    
        # Sanitize and limit release notes
        if release_body:
            # Limit to 2000 characters for most services, 1800 for Discord
            # (Discord needs room for metadata in the message)
            max_chars = 2000
            if len(release_body) > max_chars:
                release_body = release_body[:max_chars] + "..."
        
            # Remove or replace control characters (except newlines, returns, tabs)
            release_body = ''.join(char if ord(char) >= 32 or char in '\n\r\t' else '' for char in release_body)
    
        for endpoint in endpoints:
            try:
                # Resolve the actual URL (handles shared bot logic)
                real_url = self._resolve_endpoint(endpoint.endpoint)
            
                if real_url:
                    # Build appropriate body based on endpoint type
                    if real_url.startswith('tgram://'):
                        # Telegram with HTML formatting
                        body = self._build_telegram_body(repo, release_info, release_body)
                        self._send_apprise_notification(real_url, title, body, body_format='html')
                    elif 'discord' in real_url.lower():
                        # Discord with markdown (triple backticks)
                        # Use 1800 chars for Discord to leave room for metadata
                        discord_body = release_body[:1800] + '...' if len(release_body) > 1800 else release_body
                        body = self._build_discord_body(repo, release_info, discord_body)
                        self._send_apprise_notification(real_url, title, body, body_format='markdown')
                    else:
                        # Other services with text formatting
                        body = self._build_text_body(repo, release_info, release_body)
                        self._send_apprise_notification(real_url, title, body, body_format='text')
                
                    print(f"Notification sent to {user.username} via {endpoint.name}")
                else:
                    print(f"Skipping notification for {user.username}: Endpoint resolution failed ({endpoint.name})")
                
            except Exception as e:
                print(f"Error sending notification to {endpoint.name}: {e}")

    def _build_telegram_body(self, repo, release_info, release_body):
        """Build notification body with Telegram HTML formatting"""
        import html
    
        body_parts = [f"Version {html.escape(release_info['tag_name'])} has been released!"]
    
        if release_info.get('name'):
            body_parts.append(f"Release Name: {html.escape(release_info['name'])}")
    
        if release_body:
            body_parts.append("\nRelease Notes:")
            # Escape HTML entities and wrap in <pre> for monospace
            escaped_body = html.escape(release_body)
            body_parts.append(f"<pre>{escaped_body}</pre>")
    
        body_parts.append(f"\nView Release: {html.escape(release_info['html_url'])}")
    
        return '\n'.join(body_parts)

    def _build_discord_body(self, repo, release_info, release_body):
        """Build notification body with Discord markdown formatting"""
        body_parts = [f"Version {release_info['tag_name']} has been released!"]
    
        if release_info.get('name'):
            body_parts.append(f"Release Name: {release_info['name']}")
    
        if release_body:
            # Escape backticks to prevent code block injection
            # Replace ` with ′ (prime symbol)
            safe_body = release_body.replace('`', '′')
        
            body_parts.append("\nRelease Notes:")
            body_parts.append(f"```\n{safe_body}\n```")
    
        body_parts.append(f"\nView Release: {release_info['html_url']}")
    
        return '\n'.join(body_parts)

    def _build_text_body(self, repo, release_info, release_body):
        """Build notification body for text-based services"""
        body_parts = [f"Version {release_info['tag_name']} has been released!"]
    
        if release_info.get('name'):
            body_parts.append(f"Release Name: {release_info['name']}")
    
        if release_body:
            body_parts.append("\nRelease Notes:")
            body_parts.append("---")
            body_parts.append(release_body)
            body_parts.append("---")
    
        body_parts.append(f"\nView Release: {release_info['html_url']}")
    
        return '\n'.join(body_parts)

    def _send_apprise_notification(self, endpoint, title, body, body_format='text'):
        """Send notification via Apprise with specified body format"""
        try:
            import apprise
            apobj = apprise.Apprise()
            apobj.add(endpoint)
        
            # Set body format based on endpoint type
            if body_format == 'html':
                apobj.notify(title=title, body=body, body_format=apprise.NotifyFormat.HTML)
            elif body_format == 'markdown':
                apobj.notify(title=title, body=body, body_format=apprise.NotifyFormat.MARKDOWN)
            else:
                apobj.notify(title=title, body=body, body_format=apprise.NotifyFormat.TEXT)
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
            'platform': r.platform,
            'latest_release': r.latest_release,
            'latest_release_url': r.latest_release_url,
            'latest_release_body': r.latest_release_body,
            'notify_pre_releases': r.notify_pre_releases,
            'last_checked': r.last_checked.isoformat() if r.last_checked else None,
            'added_at': r.added_at.isoformat()
        } for r in repos])
    
    elif request.method == 'POST':
        data = request.json
        repo_url = data.get('repo_url', '').strip()
        requested_platform = data.get('platform', '').strip().lower() if data.get('platform') else None

        # Determine platform from URL
        platform = None
        owner = None
        name = None
        instance_url = None

        # GitHub
        if 'github.com/' in repo_url:
            platform = 'github'
            parts = repo_url.split('github.com/')[-1].strip('/').split('/')
            if len(parts) >= 2:
                owner, name = parts[0], parts[1]
            else:
                return jsonify({'error': 'Invalid GitHub URL'}), 400

        # GitLab (includes self-hosted instances)
        elif 'gitlab' in repo_url:
            platform = 'gitlab'
            # Parse the URL to extract project path and instance
            if '//' in repo_url:
                after_protocol = repo_url.split('//', 1)[1]
            else:
                after_protocol = repo_url

            if '/' in after_protocol:
                host_part = after_protocol.split('/', 1)[0]
                path_part = after_protocol.split('/', 1)[1].strip('/')
            else:
                return jsonify({'error': 'Invalid GitLab URL'}), 400

            path_parts = path_part.split('/')
            if len(path_parts) < 2:
                return jsonify({'error': 'Invalid GitLab URL: project path too short'}), 400

            # Full project path (supports subgroups)
            owner = path_part  # e.g., "group/subgroup/project" or "owner/project"
            name = path_parts[-1]

            # Detect if self-hosted
            if host_part not in ('gitlab.com', 'www.gitlab.com'):
                instance_url = host_part

        # Gitea-compatible platforms (user must specify platform via dropdown)
        elif requested_platform in GITEA_COMPATIBLE_PLATFORMS:
            platform = requested_platform
            if '//' in repo_url:
                after_protocol = repo_url.split('//', 1)[1]
            else:
                after_protocol = repo_url

            if '/' in after_protocol:
                host_part = after_protocol.split('/', 1)[0]
                path_part = after_protocol.split('/', 1)[1].strip('/')
            else:
                return jsonify({'error': 'Invalid URL: could not extract path'}), 400

            path_parts = path_part.split('/')
            if len(path_parts) < 2:
                return jsonify({'error': 'Invalid URL: project path too short (expected owner/repo)'}), 400

            owner = path_parts[0]
            name = path_parts[1]

            known_instance = GITEA_KNOWN_INSTANCES.get(platform)
            if known_instance and host_part != known_instance:
                instance_url = host_part
            elif not known_instance:
                instance_url = host_part

        else:
            return jsonify({'error': 'Unsupported repository URL. Currently supported: GitHub (github.com), GitLab (gitlab.com or self-hosted), Codeberg, Gitea, Forgejo (select platform from dropdown)'}), 400

        # Check if already exists
        existing = Repository.query.filter_by(
            user_id=session['user_id'],
            repo_url=repo_url
        ).first()

        if existing:
            return jsonify({'error': 'Repository already added'}), 400

        # Fetch initial release info
        latest = None
        try:
            api_handler = get_api_handler(platform)
            if platform == 'github':
                latest = api_handler.get_latest_release(owner, name)
            elif platform == 'gitlab':
                latest = api_handler.get_latest_release(owner, instance_url=instance_url)
            elif platform in GITEA_COMPATIBLE_PLATFORMS:
                latest = api_handler.get_latest_release(
                    owner, name, platform=platform, instance_url=instance_url
                )
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        repo = Repository(
            user_id=session['user_id'],
            repo_url=repo_url,
            repo_owner=owner,
            repo_name=name,
            platform=platform,
            instance_url=instance_url,
            latest_release=latest['tag_name'] if latest else None,
            latest_release_url=latest['html_url'] if latest else None,
            latest_release_body=latest.get('body', '') if latest else None,
            last_checked=datetime.now(timezone.utc)
        )
        db.session.add(repo)
        db.session.commit()

        return jsonify({'message': 'Repository added', 'id': repo.id}), 201

@app.route('/api/repositories/<int:repo_id>/pre-releases', methods=['PUT'])
@login_required
def toggle_pre_releases(repo_id):
    repo = Repository.query.filter_by(id=repo_id, user_id=session['user_id']).first()
    if not repo:
        return jsonify({'error': 'Repository not found'}), 404
    
    data = request.json
    repo.notify_pre_releases = data.get('enabled', False)
    db.session.commit()
    
    return jsonify({'message': 'Pre-release setting updated', 'notify_pre_releases': repo.notify_pre_releases})

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
            title="Test Notification - Hubrise Release Monitor",
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
        tokens = PlatformToken.query.all()

        return jsonify({
            'polling_interval': int(interval.value) if interval else 60,
            'registrations_enabled': reg_enabled.value == 'true' if reg_enabled else True,
            'tokens': [{
                'id': t.id,
                'token': t.token[:8] + '...',
                'platform': t.platform,
                'label': t.label,
                'instance_url': t.instance_url,
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
        platform = data.get('platform', 'github').strip().lower()
        label = data.get('label', '').strip()

        if not token:
            return jsonify({'error': 'Token required'}), 400

        if platform not in ('github', 'gitlab') + GITEA_COMPATIBLE_PLATFORMS:
            return jsonify({'error': 'Invalid platform. Supported: github, gitlab, codeberg, gitea, forgejo'}), 400

        # Validate the token by making a test call
        try:
            api_handler = get_api_handler(platform)
            if platform == 'github':
                is_valid = api_handler.test_token(token)
            elif platform == 'gitlab':
                is_valid = api_handler.test_token(token)
            elif platform in GITEA_COMPATIBLE_PLATFORMS:
                instance_url = data.get('instance_url', '').strip() or None
                is_valid = api_handler.test_token(token, platform=platform, instance_url=instance_url)
            else:
                is_valid = True

            if not is_valid:
                return jsonify({'error': f'Token validation failed for {platform}. Check the token is correct and has the right permissions.'}), 400
        except Exception as e:
            print(f"Token validation error: {e}")
            # Allow adding even if validation fails (network issue)

        instance_url_val = None
        if platform in GITEA_COMPATIBLE_PLATFORMS:
            instance_url_val = data.get('instance_url', '').strip() or None

        platform_token = PlatformToken(
            token=token,
            platform=platform,
            label=label or f"{platform.title()} Token",
            instance_url=instance_url_val
        )
        db.session.add(platform_token)
        db.session.commit()

        return jsonify({'message': f'{platform.title()} token added', 'id': platform_token.id}), 201

    elif request.method == 'DELETE':
        token_id = request.json.get('id')
        token = db.session.get(PlatformToken, token_id)
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


@app.route('/api/admin/debug-repo/<int:repo_id>', methods=['GET'])
@admin_required
def debug_repo(repo_id):
    """Debug endpoint: Test fetching the latest release for a specific repo via RAW API call.
    Bypasses the try/except in get_latest_release to show the actual error."""
    repo = db.session.get(Repository, repo_id)
    if not repo:
        return jsonify({'error': 'Repository not found'}), 404

    result = {
        'repo_id': repo.id,
        'repo_url': repo.repo_url,
        'repo_owner': repo.repo_owner,
        'repo_name': repo.repo_name,
        'platform': repo.platform,
        'instance_url': repo.instance_url,
        'notify_pre_releases': repo.notify_pre_releases,
        'current_stored': {
            'latest_release': repo.latest_release,
            'has_body': bool(repo.latest_release_body),
            'body_length': len(repo.latest_release_body or ''),
            'has_url': bool(repo.latest_release_url),
        },
        'api_test': None,
    }

    try:
        if repo.platform == 'gitlab':
            # Make the RAW API call to see the ACTUAL error
            import urllib.parse

            base_url = 'https://gitlab.com' if not repo.instance_url else f'https://{repo.instance_url}'
            encoded_path = urllib.parse.quote(repo.repo_owner, safe='')
            api_url = f'{base_url}/api/v4/projects/{encoded_path}/releases?per_page=20'

            result['api_test'] = {
                'request_url': api_url,
                'has_token': bool(gitlab_api.get_token()),
            }

            try:
                resp = requests.get(api_url, timeout=30)
                result['api_test']['http_status'] = resp.status_code
                result['api_test']['headers_received'] = dict(resp.headers)

                if resp.status_code == 200:
                    releases = resp.json()
                    result['api_test']['release_count'] = len(releases)
                    if releases:
                        r = releases[0]
                        result['api_test']['success'] = True
                        result['api_test']['tag_name'] = r.get('tag_name')
                        result['api_test']['name'] = r.get('name')
                        body = (r.get('description') or '')[:2000]
                        result['api_test']['has_body'] = bool(body)
                        result['api_test']['body_length'] = len(body)
                        result['api_test']['body_preview'] = body[:200]
                    else:
                        result['api_test']['success'] = False
                        result['api_test']['error'] = 'API returned empty releases array'
                else:
                    result['api_test']['success'] = False
                    result['api_test']['error'] = f'HTTP {resp.status_code}'
                    result['api_test']['response_body'] = resp.text[:2000]
            except requests.exceptions.SSLError as e:
                result['api_test']['success'] = False
                result['api_test']['error'] = f'SSL Error: {str(e)}'
            except requests.exceptions.ConnectionError as e:
                result['api_test']['success'] = False
                result['api_test']['error'] = f'Connection Error: {str(e)}'
            except requests.exceptions.Timeout as e:
                result['api_test']['success'] = False
                result['api_test']['error'] = f'Timeout: {str(e)}'
            except requests.exceptions.RequestException as e:
                result['api_test']['success'] = False
                result['api_test']['error'] = f'Request Error: {type(e).__name__}: {str(e)}'
        elif repo.platform == 'github':
            # For GitHub, go through the normal handler (it already has good error logging)
            api_handler = get_api_handler(repo.platform)
            latest = api_handler.get_latest_release(
                repo.repo_owner, repo.repo_name,
                include_prereleases=repo.notify_pre_releases
            )
            if latest:
                result['api_test'] = {
                    'success': True,
                    'tag_name': latest['tag_name'],
                    'name': latest['name'],
                    'has_body': bool(latest.get('body', '')),
                    'body_length': len(latest.get('body', '')),
                    'body_preview': (latest.get('body', '') or '')[:200],
                    'html_url': latest['html_url'],
                    'prerelease': latest['prerelease'],
                    'published_at': latest.get('published_at'),
                }
            else:
                result['api_test'] = {
                    'success': False,
                    'error': 'No release data returned',
                }
        elif repo.platform in GITEA_COMPATIBLE_PLATFORMS:
            # Gitea-compatible platforms (Codeberg, Gitea, Forgejo)
            base_url = gitea_api._build_base_url(repo.platform, repo.instance_url)
            api_url = f'{base_url}/api/v1/repos/{repo.repo_owner}/{repo.repo_name}/releases?limit=20'

            result['api_test'] = {
                'request_url': api_url,
                '                has_token': bool(gitea_api.get_token(repo.platform, repo.instance_url)),
                'platform': repo.platform,
            }

            try:
                headers = {}
                token = gitea_api.get_token(repo.platform, repo.instance_url)
                if token:
                    headers['Authorization'] = f'token {token}'

                resp = requests.get(api_url, headers=headers, timeout=30)
                result['api_test']['http_status'] = resp.status_code
                result['api_test']['headers_received'] = dict(resp.headers)

                if resp.status_code == 200:
                    releases = resp.json()
                    result['api_test']['release_count'] = len(releases)
                    if releases:
                        r = releases[0]
                        result['api_test']['success'] = True
                        result['api_test']['tag_name'] = r.get('tag_name')
                        result['api_test']['name'] = r.get('name')
                        body = (r.get('body') or '')[:2000]
                        result['api_test']['has_body'] = bool(body)
                        result['api_test']['body_length'] = len(body)
                        result['api_test']['body_preview'] = body[:200]
                    else:
                        result['api_test']['success'] = False
                        result['api_test']['error'] = 'API returned empty releases array'
                else:
                    result['api_test']['success'] = False
                    result['api_test']['error'] = f'HTTP {resp.status_code}'
                    result['api_test']['response_body'] = resp.text[:2000]
            except requests.exceptions.SSLError as e:
                result['api_test']['success'] = False
                result['api_test']['error'] = f'SSL Error: {str(e)}'
            except requests.exceptions.ConnectionError as e:
                result['api_test']['success'] = False
                result['api_test']['error'] = f'Connection Error: {str(e)}'
            except requests.exceptions.Timeout as e:
                result['api_test']['success'] = False
                result['api_test']['error'] = f'Timeout: {str(e)}'
            except requests.exceptions.RequestException as e:
                result['api_test']['success'] = False
                result['api_test']['error'] = f'Request Error: {type(e).__name__}: {str(e)}'
        else:
            result['api_test'] = {'error': f'Unknown platform: {repo.platform}'}
    except Exception as e:
        result['api_test'] = {'success': False, 'error': f'{type(e).__name__}: {str(e)}'}

    return jsonify(result)

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
                
                if 'notify_pre_releases' not in columns:
                    print("Migrating database: Adding notify_pre_releases column...")
                    conn.execute(text("ALTER TABLE repository ADD COLUMN notify_pre_releases BOOLEAN DEFAULT 0"))
                    conn.commit()
                    print("Migration complete!")
        except Exception as e:
            print(f"Migration check: {e}")
        
        # Migrate existing database - add platform and instance_url columns
        try:
            from sqlalchemy import text
            with db.engine.connect() as conn:
                result = conn.execute(text("PRAGMA table_info(repository)")).fetchall()
                columns = [row[1] for row in result]

                if 'platform' not in columns:
                    print("Migrating database: Adding platform column...")
                    conn.execute(text("ALTER TABLE repository ADD COLUMN platform VARCHAR(20) DEFAULT 'github'"))
                    conn.commit()
                    print("Migration complete!")

                if 'instance_url' not in columns:
                    print("Migrating database: Adding instance_url column...")
                    conn.execute(text("ALTER TABLE repository ADD COLUMN instance_url VARCHAR(500)"))
                    conn.commit()
                    print("Migration complete!")

                # Migrate github_token table - add platform and label columns
                result = conn.execute(text("PRAGMA table_info(github_token)")).fetchall()
                columns = [row[1] for row in result]

                if 'platform' not in columns:
                    print("Migrating database: Adding platform column to github_token...")
                    conn.execute(text("ALTER TABLE github_token ADD COLUMN platform VARCHAR(20) DEFAULT 'github'"))
                    conn.commit()
                    # Set existing tokens to 'github'
                    conn.execute(text("UPDATE github_token SET platform = 'github' WHERE platform IS NULL"))
                    conn.commit()
                    print("Migration complete!")

                if 'label' not in columns:
                    print("Migrating database: Adding label column to github_token...")
                    conn.execute(text("ALTER TABLE github_token ADD COLUMN label VARCHAR(100)"))
                    conn.commit()
                    # Set default labels for existing tokens
                    conn.execute(text("UPDATE github_token SET label = 'GitHub Token' WHERE label IS NULL"))
                    conn.commit()
                    print("Migration complete!")

                if 'instance_url' not in columns:
                    print("Migrating database: Adding instance_url column to github_token...")
                    conn.execute(text("ALTER TABLE github_token ADD COLUMN instance_url VARCHAR(500)"))
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
    print("Starting Hubrise Release Monitor...")
    print("Access the web interface at: http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
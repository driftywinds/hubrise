## Hubrise - Apprise Notifications for GitHub Releases

<img align="left" width="100" height="100" src="https://raw.githubusercontent.com/driftywinds/hubrise/716360dd94e32c63f207d1d50d270a1244c6354b/assets/icon.svg"> Stay up to date with your favourite GitHub Repositories.

<br>

[![Pulls](https://img.shields.io/docker/pulls/driftywinds/hubrise.svg?style=for-the-badge)](https://img.shields.io/docker/pulls/driftywinds/hubrise.svg?style=for-the-badge)

Also available on Docker Hub - [```driftywinds/hubrise:latest```](https://hub.docker.com/repository/docker/driftywinds/hubrise/general)

### How to use: - 

1. Download the ```compose.yml``` file from the repo [here](https://github.com/driftywinds/hubrise).
2. Run ```docker compose up -d```.
3. Setup the first user (which has admin privileges by default) here `https://localhost:3035` and get started.

<br>

You can check logs live with this command: - 
```
docker compose logs -f
```
### For dev testing: -
- have python3 installed on your machine
- clone the repo
- go into the directory and run these commands: -
```
python3 -m venv .venv
source .venv/bin/activate
pip install --no-cache-dir -r requirements.txt
```  
- then run ```python3 app.py```

# Local Mac Deployment Guide

This guide provides instructions for running all 5 repositories locally on a Mac for WebSocket bridge development.

## Configuration Changes Made

### 1. iYou IdP (iyou_idp)
- **Settings**: `config/settings.py`
  - `ALLOWED_HOSTS = ['localhost', '127.0.0.1']`
  - `CSRF_TRUSTED_ORIGINS` includes both localhost:8000 and localhost:8001
  - `IYOU_BASE_URL = http://localhost:8000` (default)

- **Environment**: `.env` file created with:
  - `IYOU_BASE_URL=http://localhost:8000`
  - `IYOU_SECRET_KEY` (development key)
  - `REDIS_URL=redis://127.0.0.1:6379/1`

- **OIDC Clients Registered**:
  - WUN Service (562401) - legacy client ID, now using wun-client
  - WUN Service (wun-client) - registered with redirect URI http://localhost:8001/openid/callback/
  - Polly Django (polly-django) - registered with redirect URI http://localhost:8002/openid/callback/

### 2. iYou WUN (iyou_wun)
- **Settings**: `config/settings.py`
  - `ALLOWED_HOSTS = ['localhost', '127.0.0.1']`
  - OIDC endpoints default to `http://localhost:8000`
  - Environment variables use proper `env.str()` syntax

- **Environment**: `.env` file updated with:
  - `WUN_BASE_URL=http://localhost:8001`
  - `OIDC_RP_CLIENT_ID=wun-client`
  - `OIDC_RP_CLIENT_SECRET=wun-secret`
  - All OIDC provider endpoints point to localhost:8000

### 3. Polly Django (polly_django)
- **Settings**: `config/settings.py`
  - `ALLOWED_HOSTS = ["localhost", "127.0.0.1"]`
  - All OIDC endpoints updated to `http://localhost:8000`

### 4. iYou Home (iyou_home)
- **WebSocket**: Already configured to `ws://127.0.0.1:9001` in `src-tauri/src/lib.rs`
- **Login Template**: Already configured to `ws://127.0.0.1:9001` in IdP login template

### 5. DID Rust (did_rust)
- No configuration changes needed for local deployment

## Running the Services

### Prerequisites
1. Ensure you have the following installed:
   - Python 3.10+
   - Node.js (for iyou_home)
   - Rust (for iyou_home and did_rust)
   - Redis (for IdP caching)

2. Install dependencies for each project:
   ```bash
   # For Python projects (IdP, WUN, Polly Django)
   cd iyou_idp && . .venv/bin/activate && pip install -r requirements.txt
   cd iyou_wun && . .venv/bin/activate && pip install -r requirements.txt  
   cd polly_django && . .venv/bin/activate && pip install -r requirements.txt
   
   # For iyou_home
   cd iyou_home && npm install
   ```

### Starting Services

1. **Start Redis** (required for IdP):
   ```bash
   redis-server
   ```

2. **Start iYou IdP** (port 8000):
   ```bash
   cd iyou_idp
   . .venv/bin/activate
   python manage.py runserver 8000
   ```

3. **Start iYou WUN** (port 8001):
   ```bash
   cd iyou_wun
   . .venv/bin/activate
   python manage.py runserver 8001
   ```

4. **Start Polly Django** (port 8002):
   ```bash
   cd polly_django
   . .venv/bin/activate
   python manage.py runserver 8002
   ```

5. **Start iYou Home** (WebSocket on 9001):
   ```bash
   cd iyou_home
   npm run tauri dev
   ```

### Accessing Services
- **IdP Admin**: http://localhost:8000/admin/
- **WUN Service**: http://localhost:8001/
- **Polly Django**: http://localhost:8002/
- **WebSocket Bridge**: ws://127.0.0.1:9001

### Verification
1. Check that all services are running and accessible
2. Verify WebSocket connection from IdP login page to iYou Home
3. Test OIDC authentication flow between services
4. Check that CORS headers are properly set

## Troubleshooting

### Common Issues
1. **Port conflicts**: Ensure no other services are using ports 8000, 8001, 8002, or 9001
2. **Redis not running**: Start Redis server before launching IdP
3. **Database migrations**: Run `python manage.py migrate` if you encounter database errors
4. **CORS issues**: Verify `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` settings

### Debugging WebSocket
- Check browser console for WebSocket connection errors
- Verify iYou Home is running and listening on ws://127.0.0.1:9001
- Check firewall settings if connection is blocked

## Database Management

All projects use SQLite by default:
- **IdP**: `iyou_idp/db.sqlite3`
- **WUN**: `iyou_wun/db.sqlite3`
- **Polly Django**: `polly_django/db.sqlite3`

To reset databases:
```bash
rm db.sqlite3
python manage.py migrate
```

## Environment Variables

All environment variables are configured in `.env` files in each project directory. The main variables are:

- **IdP**: `IYOU_BASE_URL`, `IYOU_SECRET_KEY`, `REDIS_URL`
- **WUN**: `WUN_BASE_URL`, OIDC client credentials, OIDC provider endpoints
- **Polly Django**: OIDC client credentials and provider endpoints (hardcoded)

## Security Notes

- These configurations are for **development only**
- Secret keys should be changed for production
- In production, use HTTPS and proper domain names
- Database and Redis should have proper authentication

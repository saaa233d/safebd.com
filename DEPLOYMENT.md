# SAFE bd deployment notes

This package is a single-process Node.js application. The backend serves the web app and its API from the same host.

## Required production settings

Set these as host environment variables before starting the service:

- NODE_ENV=production
- ADMIN_PASSWORD: unique password of at least 16 characters when creating the admin account for the first time.
- ADMIN_BOOTSTRAP_PASSWORD: use for one deployment to rotate the existing admin password, then remove it after the first successful restart. The new password is saved to the database.
- SESSION_SECRET: stable random secret of at least 32 characters. Keep the same value across restarts.
- SAFEBD_DATA_DIR: path on a persistent host disk. Database files and evidence are stored there. Do not use an ephemeral filesystem for production data.
- SAFEBD_ALLOWED_ORIGINS: exact comma-separated origins only if the web app is hosted separately. Leave blank for same-origin hosting.

Optional integrations such as Supabase, Google Drive, and Gemini only work when their own credentials are configured. Do not commit live credentials in this package.

## Start command

Install dependencies with npm install and start with npm start. Use one application instance with the persistent data directory mounted at the same path after restarts. The app uses local JSON persistence and is not configured for horizontally scaled multi-instance deployment.

## Emergency and messaging limitations

The SOS feature records an in-app alert and can notify connected SAFE bd administrators and a user's configured contacts. It does not contact Bangladesh 999. Users must call 999 directly for emergency services. SMS delivery is not configured in this package and was left unchanged for you to handle later.

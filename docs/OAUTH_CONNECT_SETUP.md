# One-Click Connect: Google + Zoom Setup (Platform Owner - One Time)

Your users never touch a console. They click **Connect Google**,
pick their Google account in the popup, approve, and done. Same for
Zoom: **Connect Zoom** → sign in on zoom.us → Allow.

You (the app owner) do the console setup **once**. The Client ID and
Client Secret go in the server `.env` - one OAuth client for Google,
one OAuth app for Zoom, shared by every organization. Each org's own
tokens are stored encrypted per-org after they connect.

---

## 1. Google (one-time, ~15 minutes)

1. Go to https://console.cloud.google.com → select (or create) a project.
2. **APIs & Services → Library**: enable **Google Calendar API** and **Gmail API**.
3. **APIs & Services → OAuth consent screen**:
   - User type: **External**.
   - Fill app name, support email, developer contact email.
   - Scopes: add `calendar`, `gmail.send`, `gmail.readonly`, `userinfo.email`.
     These are **sensitive scopes** - while testing, add your own Gmail
     under **Test users**. For real users beyond 100, Google requires
     app **verification** (takes days/weeks); until then users see an
     "unverified app" warning they can click through in testing mode.
4. **APIs & Services → Credentials → Create Credentials → OAuth client ID**:
   - Application type: **Web application**.
   - **Authorized redirect URIs**: add exactly
     `https://YOUR-DOMAIN/auth/google/callback`
     (use `http://localhost:8000/auth/google/callback` for local dev).
5. Copy the **Client ID** and **Client Secret** into `.env`:
   ```
   GOOGLE_CLIENT_ID=....apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=....
   GOOGLE_REDIRECT_URI=https://YOUR-DOMAIN/auth/google/callback
   ```

That's it for Google. Every org now connects with one click.

---

## 2. Zoom (one-time, ~15 minutes)

1. Go to https://marketplace.zoom.us → **Develop → Build App → OAuth**.
2. App name, e.g. "Strategy Call Agent". **Redirect URL for OAuth**:
   `https://YOUR-DOMAIN/auth/zoom/callback`
   (use `http://localhost:8000/auth/zoom/callback` for local dev).
3. **Scopes** (add all three):
   - `user:read` (read the connected Zoom account)
   - `meeting:write` (create/cancel meetings)
   - `meeting:read` (fetch meeting details)
4. Copy the **Client ID** and **Client Secret** into `.env`:
   ```
   ZOOM_CLIENT_ID=....
   ZOOM_CLIENT_SECRET=....
   ZOOM_REDIRECT_URI=https://YOUR-DOMAIN/auth/zoom/callback
   ```
5. **Publishing note**: while your app is in development, only Zoom
   accounts you add as testers can install it. To let any Zoom user
   connect, submit the app for Marketplace review/publish. For your
   own org's testing, development mode is enough.

---

## 3. How the one-click flow works (for your reference)

```
User clicks "Connect Google"
  → GET /auth/google/start  (server builds the Google URL with YOUR client_id)
  → browser navigates to accounts.google.com (account chooser popup/page:
     "select_account" is forced, so the user always sees their accounts)
  → user picks an account → approves scopes
  → Google redirects to /auth/google/callback?code=...&state=...
  → server validates state (CSRF), exchanges code for tokens with YOUR
    client_secret, stores ONLY the org's refresh_token (encrypted)
  → dashboard shows "Connected - user@gmail.com"

Zoom is identical, via zoom.us/oauth/authorize.
```

What changed from the old design:
- **Before**: every org pasted its own Client ID/Secret/Redirect URI from
  the Google/Zoom consoles into the dashboard before Connect would work.
- **Now**: the dashboard has no credential fields for Google/Zoom at all.
  One Connect button per provider. If the platform `.env` is missing the
  client, the dashboard says the administrator must finish the one-time
  setup instead of asking the org for keys.
- Old orgs that already saved their own console credentials keep working
  (their vault values are used as a legacy fallback).

## 4. Checklist before going live

- [ ] `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_REDIRECT_URI` set (production domain, https)
- [ ] Redirect URI registered in Google Cloud Console (exact match)
- [ ] Gmail + Calendar APIs enabled
- [ ] `ZOOM_CLIENT_ID` / `ZOOM_CLIENT_SECRET` / `ZOOM_REDIRECT_URI` set
- [ ] Redirect URL allowlisted in the Zoom Marketplace app
- [ ] (Later, for >100 Google users) Google OAuth verification submitted
- [ ] (Later, for other companies' Zoom accounts) Zoom app published

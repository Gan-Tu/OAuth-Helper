const express = require('express');
const axios = require('axios');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 8080;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

// Healthcheck
app.get('/health', (_req, res) => res.json({ ok: true }));

// In-memory map to keep per-flow config keyed by OAuth state param
const pending = new Map();

// Start OAuth: user posts provider + client creds; we respond with authUrl
app.post('/api/authorize', async (req, res) => {
  try {
    const { provider, client_id, client_secret, scope } = req.body || {};

    if (!provider || !client_id || !client_secret) {
      return res.status(400).json({ error: 'provider, client_id, client_secret are required' });
    }

    const { nanoid } = await import('nanoid');
    const state = nanoid(21);
    pending.set(state, { provider, client_id, client_secret, createdAt: Date.now() });

    if (provider === 'google') {
      const scopes = (scope && String(scope).trim().length > 0) ? scope : undefined;

      const params = new URLSearchParams({
        client_id,
        response_type: 'code',
        redirect_uri: `${BASE_URL}/auth/google/callback`,
        include_granted_scopes: 'true',
        state,
        access_type: 'offline',
        prompt: 'consent'
      });
      if (scopes) params.set('scope', scopes);

      const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
      return res.json({ authUrl, state, redirect_uri: `${BASE_URL}/auth/google/callback` });
    }

    if (provider === 'dropbox') {
      const params = new URLSearchParams({
        response_type: 'code',
        client_id,
        redirect_uri: `${BASE_URL}/auth/dropbox/callback`,
        state,
        token_access_type: 'offline'
      });
      const authUrl = `https://www.dropbox.com/oauth2/authorize?${params.toString()}`;
      return res.json({ authUrl, state, redirect_uri: `${BASE_URL}/auth/dropbox/callback` });
    }

    return res.status(400).json({ error: 'Unsupported provider' });
  } catch (err) {
    console.error('Authorize error', err);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// OAuth callbacks
app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) {
    return res.status(400).send(`<pre>Google OAuth error: ${String(error)}</pre>`);
  }
  const record = pending.get(state);
  if (!record || record.provider !== 'google') {
    return res.status(400).send('<pre>Invalid or expired state</pre>');
  }
  try {
    const body = new URLSearchParams({
      client_id: record.client_id,
      client_secret: record.client_secret,
      code,
      grant_type: 'authorization_code',
      redirect_uri: `${BASE_URL}/auth/google/callback`
    });
    const response = await axios.post('https://oauth2.googleapis.com/token', body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    pending.delete(state);
    return res.send(renderStoreAndRedirect('google', response.data));
  } catch (e) {
    console.error('Google token exchange failed', e.response?.data || e.message || e);
    return res.status(500).send(`<pre>Failed to exchange code: ${escapeHtml(JSON.stringify(e.response?.data || e.message || {}, null, 2))}</pre>`);
  }
});

app.get('/auth/dropbox/callback', async (req, res) => {
  const { code, state, error_description, error } = req.query;
  if (error || error_description) {
    return res.status(400).send(`<pre>Dropbox OAuth error: ${escapeHtml(String(error_description || error))}</pre>`);
  }
  const record = pending.get(state);
  if (!record || record.provider !== 'dropbox') {
    return res.status(400).send('<pre>Invalid or expired state</pre>');
  }
  try {
    const body = new URLSearchParams({
      code,
      grant_type: 'authorization_code',
      client_id: record.client_id,
      client_secret: record.client_secret,
      redirect_uri: `${BASE_URL}/auth/dropbox/callback`
    });
    const tokenResp = await axios.post('https://api.dropboxapi.com/oauth2/token', body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    pending.delete(state);
    const data = tokenResp.data || {};
    return res.send(renderStoreAndRedirect('dropbox', data));
  } catch (e) {
    console.error('Dropbox token exchange failed', e.response?.data || e.message || e);
    return res.status(500).send(`<pre>Failed to exchange code: ${escapeHtml(JSON.stringify(e.response?.data || e.message || {}, null, 2))}</pre>`);
  }
});

// Refresh token flow
app.post('/api/refresh', async (req, res) => {
  const { provider, client_id, client_secret, refresh_token } = req.body || {};
  if (!provider || !client_id || !client_secret || !refresh_token) {
    return res.status(400).json({ error: 'provider, client_id, client_secret, refresh_token are required' });
  }

  try {
    if (provider === 'google') {
      const body = new URLSearchParams({
        client_id,
        client_secret,
        refresh_token,
        grant_type: 'refresh_token'
      });
      const resp = await axios.post('https://oauth2.googleapis.com/token', body.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      return res.json(resp.data);
    }
    if (provider === 'dropbox') {
      const body = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token,
        client_id,
        client_secret
      });
      const resp = await axios.post('https://api.dropboxapi.com/oauth2/token', body.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      return res.json(resp.data);
    }
    return res.status(400).json({ error: 'Unsupported provider' });
  } catch (e) {
    console.error('Refresh failed', e.response?.data || e.message || e);
    return res.status(400).json({ error: e.response?.data || e.message || 'Refresh failed' });
  }
});

// Simple token result renderer
function renderTokenResult(provider, data) {
  const pretty = escapeHtml(JSON.stringify(data, null, 2));
  return `<!doctype html>
  <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>${provider} OAuth Result</title>
      <style>
        body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 2rem; }
        pre { background: #111; color: #eaeaea; padding: 1rem; border-radius: 8px; overflow: auto; }
        a { color: #0366d6; text-decoration: none; }
        .box { margin: 1rem 0; }
      </style>
    </head>
    <body>
      <h1>${provider} OAuth tokens</h1>
      <div class="box">
        <p>Copy the tokens below. This page is served from your local dev app.</p>
      </div>
      <pre>${pretty}</pre>
      <div class="box"><a href="/">Back to start</a></div>
    </body>
  </html>`;
}

function renderStoreAndRedirect(provider, data) {
  const payload = { provider, data };
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  return `<!doctype html>
  <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>OAuth Result</title>
    </head>
    <body>
      <script>
        (function() {
          try {
            var decoded = atob('${b64}');
            localStorage.setItem('oauth_helper_last_tokens', decoded);
          } catch (e) {}
          location.replace('/');
        })();
      </script>
      <noscript>
        <p>Tokens received. Please <a href="/">return to start</a>.</p>
      </noscript>
    </body>
  </html>`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`OAuth Helper running on ${BASE_URL}`);
  console.log(`Google redirect URI: ${BASE_URL}/auth/google/callback`);
  console.log(`Dropbox redirect URI: ${BASE_URL}/auth/dropbox/callback`);
});

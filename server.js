const express = require('express');
const axios = require('axios');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 8080;
const BASE_URL = process.env.BASE_URL;

// Respect reverse proxies (X-Forwarded-Proto/Host) so req.protocol/host are accurate
app.set('trust proxy', true);

function getBaseUrl(req) {
  // If BASE_URL is explicitly provided, prefer it
  if (BASE_URL && BASE_URL.trim().length > 0) return BASE_URL;
  const host = req.get('host');
  const protocol = req.protocol;
  return `${protocol}://${host}`;
}

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
      const baseUrl = getBaseUrl(req);
      const scopes = (scope && String(scope).trim().length > 0) ? scope : undefined;

      const params = new URLSearchParams({
        client_id,
        response_type: 'code',
        redirect_uri: `${baseUrl}/auth/google/callback`,
        include_granted_scopes: 'true',
        state,
        access_type: 'offline',
        prompt: 'consent'
      });
      if (scopes) params.set('scope', scopes);

      const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
      return res.json({ authUrl, state, redirect_uri: `${baseUrl}/auth/google/callback` });
    }

    if (provider === 'dropbox') {
      const baseUrl = getBaseUrl(req);
      const params = new URLSearchParams({
        response_type: 'code',
        client_id,
        redirect_uri: `${baseUrl}/auth/dropbox/callback`,
        state,
        token_access_type: 'offline'
      });
      const authUrl = `https://www.dropbox.com/oauth2/authorize?${params.toString()}`;
      return res.json({ authUrl, state, redirect_uri: `${baseUrl}/auth/dropbox/callback` });
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
      redirect_uri: `${getBaseUrl(req)}/auth/google/callback`
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
      redirect_uri: `${getBaseUrl(req)}/auth/dropbox/callback`
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
  console.log(`OAuth Helper running on http://localhost:${PORT}`);
});

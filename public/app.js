(() => {
  const $ = (id) => document.getElementById(id);

  const gRedirect = `${location.origin}/auth/google/callback`;
  const dRedirect = `${location.origin}/auth/dropbox/callback`;
  $('g-redirect').textContent = gRedirect;
  $('d-redirect').textContent = dRedirect;

  // On load, show tokens stored by callback and repopulate inputs
  try {
    const saved = localStorage.getItem('oauth_helper_last_tokens');
    if (saved) {
      const obj = JSON.parse(saved);
      if (obj && obj.data) {
        const pretty = JSON.stringify(obj.data, null, 2);
        const box = $('auth-result');
        if (box) box.innerHTML = `<pre style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(pretty)}</pre>`;
        if (obj.data.refresh_token && $('r_refresh_token')) {
          $('r_refresh_token').value = obj.data.refresh_token;
        }
      }
      localStorage.removeItem('oauth_helper_last_tokens');
    }
  } catch (_) { }

  try {
    const lastAuth = localStorage.getItem('oauth_helper_last_auth_request');
    if (lastAuth) {
      const a = JSON.parse(lastAuth);
      if (a) {
        if (a.provider && $('provider')) $('provider').value = a.provider;
        if (a.client_id && $('client_id')) $('client_id').value = a.client_id;
        if (a.client_secret && $('client_secret')) $('client_secret').value = a.client_secret;
        // Also set refresh inputs for convenience
        if (a.provider && $('r_provider')) $('r_provider').value = a.provider;
        if (a.client_id && $('r_client_id')) $('r_client_id').value = a.client_id;
        if (a.client_secret && $('r_client_secret')) $('r_client_secret').value = a.client_secret;
        updateScopeVisibility();
      }
      // keep it for next time; comment out the next line to persist across reloads
      // localStorage.removeItem('oauth_helper_last_auth_request');
    }
  } catch (_) { }

  $('start').addEventListener('click', async () => {
    const provider = $('provider').value;
    const client_id = $('client_id').value.trim();
    const client_secret = $('client_secret').value.trim();
    const scope = $('scope').value.trim();
    const request_offline = true; // always request refresh token

    $('auth-result').innerHTML = '';
    if (!provider || !client_id || !client_secret) {
      $('auth-result').innerHTML = '<div style="color:red">Please fill provider, client id and secret</div>';
      return;
    }
    // Google requires a non-empty scope
    if (provider === 'google' && !scope) {
      $('auth-result').innerHTML = '<div style="color:red">For Google, please provide at least one scope.</div>';
      return;
    }

    try {
      // Persist current inputs so we can restore after redirect
      try {
        localStorage.setItem('oauth_helper_last_auth_request', JSON.stringify({ provider, client_id, client_secret }));
      } catch (_) { }
      const resp = await fetch('/api/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, client_id, client_secret, scope, request_offline })
      });
      const data = await resp.json();
      if (!resp.ok) throw data;
      // Redirect to provider auth page
      window.location = data.authUrl;
    } catch (e) {
      $('auth-result').innerHTML = `<pre style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(JSON.stringify(e, null, 2))}</pre>`;
    }
  });

  // Hide scopes when provider is Dropbox
  function updateScopeVisibility() {
    const provider = $('provider').value;
    const scopeGroup = document.getElementById('scope-group');
    if (scopeGroup) scopeGroup.style.display = provider === 'dropbox' ? 'none' : '';
  }
  $('provider').addEventListener('change', updateScopeVisibility);
  updateScopeVisibility();

  $('refresh').addEventListener('click', async () => {
    const provider = $('r_provider').value;
    const client_id = $('r_client_id').value.trim();
    const client_secret = $('r_client_secret').value.trim();
    const refresh_token = $('r_refresh_token').value.trim();
    $('refresh-result').innerHTML = '';
    if (!provider || !client_id || !client_secret || !refresh_token) {
      $('refresh-result').innerHTML = '<div style="color:red">Please fill all fields</div>';
      return;
    }
    try {
      const resp = await fetch('/api/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, client_id, client_secret, refresh_token })
      });
      const data = await resp.json();
      if (!resp.ok) throw data;
      $('refresh-result').innerHTML = `<pre style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(JSON.stringify(data, null, 2))}</pre>`;
    } catch (e) {
      $('refresh-result').innerHTML = `<pre style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(JSON.stringify(e, null, 2))}</pre>`;
    }
  });

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
})();

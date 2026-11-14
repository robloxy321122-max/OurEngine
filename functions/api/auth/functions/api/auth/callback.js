export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");

  if (!state || !code || !cookies.oe_oauth_state ||
      !constantTimeEqual(state, cookies.oe_oauth_state)) {
    return redirectError(url.origin);
  }
  if (!env.DISCORD_CLIENT_ID || !env.DISCORD_CLIENT_SECRET || !env.SESSION_SECRET) {
    return new Response("Server sign-in settings are incomplete.", { status: 503 });
  }

  const redirectUri = `${url.origin}/api/auth/callback`;
  const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri
    })
  });
  if (!tokenResponse.ok) return redirectError(url.origin);
  const tokenData = await tokenResponse.json();

  const userResponse = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${tokenData.access_token}` }
  });
  if (!userResponse.ok) return redirectError(url.origin);
  const user = await userResponse.json();

  // Store only the minimum display identity in a signed, HttpOnly cookie.
  const session = {
    id: user.id,
    username: user.username,
    global_name: user.global_name || null,
    avatar: user.avatar || null,
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7
  };
  const payload = base64url(JSON.stringify(session));
  const signature = await hmac(payload, env.SESSION_SECRET);

  return new Response(null, {
    status: 302,
    headers: {
      Location: url.origin,
      "Set-Cookie": [
        `oe_session=${payload}.${signature}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
        "oe_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=0"
      ].join(", ")
    }
  });
}
function parseCookies(value) {
  return Object.fromEntries(value.split(";").map(v => v.trim()).filter(Boolean).map(v => {
    const i = v.indexOf("="); return [v.slice(0, i), v.slice(i + 1)];
  }));
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0; for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
function base64url(value) {
  return btoa(unescape(encodeURIComponent(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function redirectError(origin) {
  return new Response(null, { status: 302, headers: {
    Location: `${origin}/?error=oauth`,
    "Set-Cookie": "oe_oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=0"
  }});
}

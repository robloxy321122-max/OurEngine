import { detectUser } from "./user-detector.js";

const COOKIE_NAME = "ourengine_session";
const STATE_COOKIE = "ourengine_oauth_state";

const DISCORD_API = "https://discord.com/api/v10";
const DISCORD_AUTH = "https://discord.com/oauth2/authorize";
const DISCORD_TOKEN = "https://discord.com/api/v10/oauth2/token";

// ==========================================
// MAIN WORKER
// ==========================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // HEALTH CHECK
      if (url.pathname === "/api/health") {
        return json({ status: "online", service: "OurEngine" });
      }

      // DISCORD LOGIN
      if (url.pathname === "/api/auth/discord") {
        return startDiscordLogin(url, env);
      }

      // DISCORD CALLBACK
      if (url.pathname === "/api/auth/discord/callback") {
        return handleDiscordCallback(request, env);
      }

      // CURRENT USER
      if (url.pathname === "/api/me") {
        const session = await getSession(request, env);

        if (!session) {
          return json({ authenticated: false }, 401);
        }

        return json({
          authenticated: true,
          user: session.user
        });
      }

      // LOGOUT
      if (url.pathname === "/api/logout") {
        const response = Response.redirect(url.origin, 302);

        response.headers.append(
          "Set-Cookie",
          `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
        );

        return response;
      }

      // DASHBOARD
      if (url.pathname === "/dashboard") {
        const session = await getSession(request, env);

        if (!session) {
          return Response.redirect(url.origin, 302);
        }

        return env.ASSETS.fetch(
          new Request(new URL("/dashboard.html", url.origin), request)
        );
      }

      // OTHER API ROUTES
      if (url.pathname.startsWith("/api/")) {
        return json({ error: "API route not found" }, 404);
      }

      // WEBSITE FILES
      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error("[OurEngine] Worker error:", error);

      return json({
        error: "Internal server error"
      }, 500);
    }
  }
};

// ==========================================
// DISCORD LOGIN
// ==========================================

function startDiscordLogin(url, env) {
  if (!env.DISCORD_CLIENT_ID || !env.DISCORD_CLIENT_SECRET) {
    return json({
      error: "Discord OAuth configuration is missing"
    }, 500);
  }

  const state = randomToken();

  const callbackUrl =
    `${url.origin}/api/auth/discord/callback`;

  const discordUrl = new URL(DISCORD_AUTH);

  discordUrl.searchParams.set(
    "client_id",
    env.DISCORD_CLIENT_ID
  );

  discordUrl.searchParams.set(
    "redirect_uri",
    callbackUrl
  );

  discordUrl.searchParams.set(
    "response_type",
    "code"
  );

  discordUrl.searchParams.set(
    "scope",
    "identify"
  );

  discordUrl.searchParams.set(
    "state",
    state
  );

  const response = Response.redirect(discordUrl.toString(), 302);

  response.headers.append(
    "Set-Cookie",
    `${STATE_COOKIE}=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
  );

  return response;
}

// ==========================================
// DISCORD CALLBACK
// ==========================================

async function handleDiscordCallback(request, env) {
  const url = new URL(request.url);

  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");

  const cookies = parseCookies(request.headers.get("Cookie"));

  const savedState = cookies[STATE_COOKIE];

  if (!code || !returnedState || returnedState !== savedState) {
    return json({
      error: "Invalid Discord login request"
    }, 400);
  }

  // Exchange Discord authorization code
  const callbackUrl =
    `${url.origin}/api/auth/discord/callback`;

  const tokenResponse = await fetch(DISCORD_TOKEN, {
    method: "POST",

    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },

    body: new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      client_secret: env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: callbackUrl
    })
  });

  if (!tokenResponse.ok) {
    console.error("[OurEngine] Discord token exchange failed");

    return json({
      error: "Discord authentication failed"
    }, 401);
  }

  const tokenData = await tokenResponse.json();

  // Retrieve Discord user
  const userResponse = await fetch(`${DISCORD_API}/users/@me`, {
    headers: {
      Authorization: `Bearer ${tokenData.access_token}`
    }
  });

  if (!userResponse.ok) {
    return json({
      error: "Could not retrieve Discord user"
    }, 401);
  }

  const user = await userResponse.json();

  // ========================================
  // SEPARATE USER DETECTOR
  // ========================================

  detectUser(user);

  // ========================================
  // CREATE LOGIN SESSION
  // ========================================

  const session = {
    user: {
      id: user.id,
      username: user.username,
      global_name: user.global_name,
      avatar: user.avatar
    },

    exp: Math.floor(Date.now() / 1000) + 86400
  };

  const signedSession = await signSession(
    session,
    env.DISCORD_CLIENT_SECRET
  );

  const response = Response.redirect(
    `${url.origin}/dashboard`,
    302
  );

  response.headers.append(
    "Set-Cookie",
    `${COOKIE_NAME}=${signedSession}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`
  );

  response.headers.append(
    "Set-Cookie",
    `${STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
  );

  return response;
}

// ==========================================
// SESSION SIGNING
// ==========================================

async function signSession(session, secret) {
  const payload = base64urlEncode(
    JSON.stringify(session)
  );

  const signature = await createSignature(payload, secret);

  return `${payload}.${signature}`;
}

async function createSignature(payload, secret) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload)
  );

  return base64urlEncode(
    String.fromCharCode(...new Uint8Array(signature))
  );
}

// ==========================================
// VERIFY SESSION
// ==========================================

async function getSession(request, env) {
  const cookies = parseCookies(
    request.headers.get("Cookie")
  );

  const value = cookies[COOKIE_NAME];

  if (!value || !env.DISCORD_CLIENT_SECRET) {
    return null;
  }

  const parts = value.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [payload, signature] = parts;

  const expectedSignature = await createSignature(
    payload,
    env.DISCORD_CLIENT_SECRET
  );

  if (signature !== expectedSignature) {
    return null;
  }

  try {
    const session = JSON.parse(
      base64urlDecode(payload)
    );

    if (session.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return session;

  } catch {
    return null;
  }
}

// ==========================================
// COOKIE UTILITIES
// ==========================================

function parseCookies(cookieHeader = "") {
  const cookies = {};

  cookieHeader.split(";").forEach(cookie => {
    const separator = cookie.indexOf("=");

    if (separator === -1) return;

    const name = cookie.slice(0, separator).trim();
    const value = cookie.slice(separator + 1).trim();

    cookies[name] = value;
  });

  return cookies;
}

// ==========================================
// RANDOM STATE
// ==========================================

function randomToken() {
  const bytes = crypto.getRandomValues(
    new Uint8Array(32)
  );

  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

// ==========================================
// BASE64 UTILITIES
// ==========================================

function base64urlEncode(value) {
  const bytes = new TextEncoder().encode(value);

  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function base64urlDecode(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = base64.padEnd(
    Math.ceil(base64.length / 4) * 4,
    "="
  );

  const binary = atob(padded);

  const bytes = Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );

  return new TextDecoder().decode(bytes);
}

// ==========================================
// JSON RESPONSE
// ==========================================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,

    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

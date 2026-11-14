const COOKIE_NAME = "ourengine_session";
const STATE_COOKIE = "ourengine_oauth_state";

const REDIRECT_URI =
  "https://ourengine.ourengine.workers.dev/api/auth/discord/callback";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // HEALTH CHECK
      if (url.pathname === "/api/health") {
        return Response.json({
          status: "online",
          project: "OurEngine"
        });
      }

      // START DISCORD LOGIN
      if (
        url.pathname === "/api/auth/discord" &&
        request.method === "GET"
      ) {
        if (!env.DISCORD_CLIENT_ID || !env.DISCORD_CLIENT_SECRET) {
          return Response.json(
            { error: "Discord configuration is missing." },
            { status: 500 }
          );
        }

        const state = randomString(32);

        const discordURL = new URL(
          "https://discord.com/oauth2/authorize"
        );

        discordURL.searchParams.set(
          "client_id",
          env.DISCORD_CLIENT_ID
        );

        discordURL.searchParams.set(
          "redirect_uri",
          REDIRECT_URI
        );

        discordURL.searchParams.set(
          "response_type",
          "code"
        );

        discordURL.searchParams.set(
          "scope",
          "identify"
        );

        discordURL.searchParams.set("state", state);

        return new Response(null, {
          status: 302,
          headers: {
            Location: discordURL.toString(),
            "Set-Cookie":
              `${STATE_COOKIE}=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
          }
        });
      }

      // DISCORD CALLBACK
      if (
        url.pathname === "/api/auth/discord/callback" &&
        request.method === "GET"
      ) {
        const code = url.searchParams.get("code");
        const returnedState = url.searchParams.get("state");
        const savedState = getCookie(request, STATE_COOKIE);

        if (
          !code ||
          !returnedState ||
          !savedState ||
          returnedState !== savedState
        ) {
          return Response.json(
            { error: "Invalid login request. Please try again." },
            { status: 400 }
          );
        }

        // EXCHANGE CODE FOR ACCESS TOKEN
        const tokenResponse = await fetch(
          "https://discord.com/api/v10/oauth2/token",
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
              client_id: env.DISCORD_CLIENT_ID,
              client_secret: env.DISCORD_CLIENT_SECRET,
              grant_type: "authorization_code",
              code: code,
              redirect_uri: REDIRECT_URI
            })
          }
        );

        if (!tokenResponse.ok) {
          return Response.json(
            { error: "Discord authorization failed." },
            { status: 401 }
          );
        }

        const tokenData = await tokenResponse.json();

        // GET DISCORD USER
        const userResponse = await fetch(
          "https://discord.com/api/v10/users/@me",
          {
            headers: {
              Authorization:
                `Bearer ${tokenData.access_token}`
            }
          }
        );

        if (!userResponse.ok) {
          return Response.json(
            { error: "Could not retrieve Discord account." },
            { status: 401 }
          );
        }

        const user = await userResponse.json();

        // CREATE SIGNED SESSION
        const session = {
          id: user.id,
          username: user.username,
          global_name: user.global_name || user.username,
          avatar: user.avatar,
          exp: Math.floor(Date.now() / 1000) + 86400
        };

        const sessionValue = await signSession(
          session,
          env.DISCORD_CLIENT_SECRET
        );

        return new Response(null, {
          status: 302,
          headers: {
            Location: "/dashboard",
            "Set-Cookie": [
              `${COOKIE_NAME}=${sessionValue}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`,
              `${STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
            ].join(", ")
          }
        });
      }

      // CURRENT USER
      if (url.pathname === "/api/me") {
        const session = await getSession(request, env);

        if (!session) {
          return Response.json(
            { authenticated: false },
            { status: 401 }
          );
        }

        return Response.json({
          authenticated: true,
          user: session
        });
      }

      // LOGOUT
      if (url.pathname === "/api/logout") {
        return new Response(
          JSON.stringify({ success: true }),
          {
            headers: {
              "Content-Type": "application/json",
              "Set-Cookie":
                `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
            }
          }
        );
      }

      // OTHER API ROUTES
      if (url.pathname.startsWith("/api/")) {
        return Response.json(
          { error: "API route not found." },
          { status: 404 }
        );
      }

      // SERVE WEBSITE
      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error("OurEngine error:", error);

      return Response.json(
        { error: "An internal server error occurred." },
        { status: 500 }
      );
    }
  }
};


// RANDOM STATE GENERATOR
function randomString(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}


// READ COOKIE
function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";

  const item = cookies
    .split(";")
    .map(cookie => cookie.trim())
    .find(cookie => cookie.startsWith(name + "="));

  return item ? item.substring(name.length + 1) : null;
}


// BASE64 URL ENCODING
function base64url(value) {
  const bytes = new TextEncoder().encode(value);

  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}


// SIGN SESSION
async function signSession(session, secret) {
  const payload = base64url(JSON.stringify(session));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
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
    new TextEncoder().encode(payload)
  );

  const signatureBytes = new Uint8Array(signature);

  let binary = "";

  for (const byte of signatureBytes) {
    binary += String.fromCharCode(byte);
  }

  const encodedSignature = btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return `${payload}.${encodedSignature}`;
}


// VERIFY SESSION
async function getSession(request, env) {
  const value = getCookie(request, COOKIE_NAME);

  if (!value || !env.DISCORD_CLIENT_SECRET) {
    return null;
  }

  const parts = value.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [payload, signature] = parts;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.DISCORD_CLIENT_SECRET),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const signatureBytes = Uint8Array.from(
    atob(
      signature.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - signature.length % 4) % 4)
    ),
    character => character.charCodeAt(0)
  );

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    new TextEncoder().encode(payload)
  );

  if (!valid) {
    return null;
  }

  try {
    const decoded = atob(
      payload.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - payload.length % 4) % 4)
    );

    const session = JSON.parse(decoded);

    if (session.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return session;

  } catch {
    return null;
  }
}

export async function onRequestGet({ request, env }) {
  const cookies = Object.fromEntries((request.headers.get("Cookie") || "")
    .split(";").map(v => v.trim()).filter(Boolean).map(v => {
      const i = v.indexOf("="); return [v.slice(0, i), v.slice(i + 1)];
    }));
  const value = cookies.oe_session || "";
  const splitAt = value.lastIndexOf(".");
  if (splitAt < 1 || !env.SESSION_SECRET) {
    return Response.json({ user: null }, { headers: { "Cache-Control": "no-store" } });
  }
  const payload = value.slice(0, splitAt);
  const signature = value.slice(splitAt + 1);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const raw = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  const expected = btoa(String.fromCharCode(...new Uint8Array(raw)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  if (!constantTimeEqual(signature, expected)) {
    return Response.json({ user: null }, { headers: { "Cache-Control": "no-store" } });
  }
  try {
    const decoded = JSON.parse(decodeURIComponent(escape(atob(payload.replace(/-/g, "+").replace(/_/g, "/")))));
    if (!decoded.exp || decoded.exp < Date.now() / 1000) {
      return Response.json({ user: null }, { headers: { "Cache-Control": "no-store" } });
    }
    return Response.json({ user: {
      id: decoded.id, username: decoded.username,
      global_name: decoded.global_name, avatar: decoded.avatar
    }}, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ user: null }, { headers: { "Cache-Control": "no-store" } });
  }
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0; for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

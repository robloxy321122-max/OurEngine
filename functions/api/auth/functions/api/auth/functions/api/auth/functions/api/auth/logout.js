export async function onRequestPost() {
  return new Response(null, { status: 204, headers: {
    "Set-Cookie": "oe_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
    "Cache-Control": "no-store"
  }});
}

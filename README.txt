OURENGINE — DISCORD SIGN-IN STARTER

This is a Cloudflare Pages project with Discord OAuth sign-in.
It requests only the Discord "identify" scope. It does NOT request access to
servers, messages, friends, or the user's Discord password.

PUBLISH:
1. In Cloudflare, open Workers & Pages > your Pages project.
2. Upload this ZIP as a new deployment (or create a new Pages project).
3. Ensure the project is deployed as a Pages project with Functions enabled.
   The /functions folder must remain at the project root.

CREATE DISCORD OAUTH APP:
1. Open https://discord.com/developers/applications
2. Create a New Application and give it a name such as OurEngine.
3. Open OAuth2 > General.
4. Add this exact Redirect URL after you know your deployed hostname:
   https://YOUR-PROJECT.pages.dev/api/auth/callback
5. Save changes.
6. Copy the Client ID. Use Reset Secret / Client Secret to obtain the secret.
   NEVER put the Client Secret in HTML, JavaScript, a screenshot, or a message.

ADD CLOUDFLARE SECRETS:
In your Pages project settings, open Settings > Variables and Secrets
(or Functions > Variables and Secrets, depending on dashboard layout).
Add these as encrypted secrets:
- DISCORD_CLIENT_ID = your Discord application Client ID
- DISCORD_CLIENT_SECRET = your Discord application Client Secret
- SESSION_SECRET = a long random secret (at least 32 random characters)
Redeploy after adding/changing secrets if Cloudflare asks.

Then test Sign in with Discord on the deployed site.

IMPORTANT:
- This creates sign-in and a basic signed session only.
- It does not automatically make someone an OurEngine administrator.
- Do not trust a role or admin flag stored in browser JavaScript.
- Before adding private dashboards or admin actions, authorize specific Discord
  user IDs on the server and protect every private API endpoint.
- Never share your Discord Client Secret or SESSION_SECRET.

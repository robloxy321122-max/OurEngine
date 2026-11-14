export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // OurEngine health check
    if (url.pathname === "/api/health") {
      return Response.json({
        status: "online",
        project: "OurEngine"
      });
    }

    // Discord API routes will be added next
    if (url.pathname.startsWith("/api/")) {
      return Response.json(
        { error: "API route not configured yet" },
        { status: 404 }
      );
    }

    // Serve the website
    return env.ASSETS.fetch(request);
  }
};

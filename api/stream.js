// ============================
// 🔥 Stream API - DISABLED
// ============================
// This endpoint has been disabled for security reasons.
// Video streaming should be handled through your CDN with signed URLs.

export default function handler(req, res) {
  // Log all access attempts
  const ip = req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.connection?.remoteAddress || "unknown";

  console.warn("[STREAM_DISABLED] Access attempt blocked:", {
    ip,
    url: req.query.url?.substring(0, 100),
    userAgent: req.headers["user-agent"]?.substring(0, 100),
    timestamp: new Date().toISOString()
  });

  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cache-Control", "no-store");

  // Return 404 to hide the endpoint
  return res.status(404).json({
    error: "Not found",
    message: "This endpoint is no longer available"
  });
}

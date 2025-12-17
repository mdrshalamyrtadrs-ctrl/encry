export default function handler(req, res) {
  // Log blocked access attempts for security monitoring
  const ip = req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.connection?.remoteAddress || "unknown";
  const path = req.url || "unknown";
  const userAgent = req.headers["user-agent"]?.substring(0, 200) || "unknown";

  console.warn("Blocked access attempt:", {
    ip,
    path,
    userAgent: userAgent.substring(0, 100),
    timestamp: new Date().toISOString()
  });

  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cache-Control", "no-store");

  // Return 404 instead of 403 to avoid information disclosure
  res.status(404).json({
    error: "Not Found",
    message: "The requested resource does not exist"
  });
}

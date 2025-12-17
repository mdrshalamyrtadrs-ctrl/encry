import crypto from "crypto";

// Rate limiting
const requestCounts = new Map();

function isRateLimited(ip, maxRequests = 10, windowMs = 60000) {
  const now = Date.now();

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, []);
  }

  const requests = requestCounts.get(ip).filter(time => time > now - windowMs);
  requests.push(now);
  requestCounts.set(ip, requests);

  return requests.length > maxRequests;
}

export default function handler(req, res) {
  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cache-Control", "no-store, max-age=0");

  const ip = req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.connection?.remoteAddress || "unknown";

  // Rate limiting
  if (isRateLimited(ip)) {
    return res.status(429).json({ error: "Too many requests" });
  }

  const site = process.env.SITE_URL;
  const origin = req.headers.origin || "";
  const referer = req.headers.referer || "";

  // Strict origin validation
  if (!site) {
    console.error("SITE_URL not configured");
    return res.status(500).json({ error: "Server configuration error" });
  }

  const siteUrl = new URL(site);
  let isValidOrigin = false;

  try {
    if (origin) {
      const originUrl = new URL(origin);
      isValidOrigin = originUrl.host === siteUrl.host;
    }
    if (!isValidOrigin && referer) {
      const refererUrl = new URL(referer);
      isValidOrigin = refererUrl.host === siteUrl.host;
    }
  } catch {
    isValidOrigin = false;
  }

  if (!isValidOrigin) {
    return res.status(403).json({ error: "Forbidden" });
  }

  // Verify session token is present
  const sessionToken = req.headers["authorization"]?.replace("Bearer ", "");
  if (!sessionToken) {
    return res.status(401).json({ error: "Authentication required" });
  }

  try {
    const staticKey = process.env.INTERNAL_KEY;
    if (!staticKey) {
      console.error("INTERNAL_KEY not configured");
      return res.status(500).json({ error: "Server configuration error" });
    }

    // Dynamic key with shorter validity (30 seconds)
    const currentWindow = Math.floor(Date.now() / 30000);

    // Include session token in the HMAC for binding
    const dynamicKey = crypto
      .createHmac("sha256", staticKey)
      .update(`${currentWindow}:${sessionToken.substring(0, 32)}`)
      .digest("hex");

    // Set CORS for valid origin only
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }

    res.status(200).json({
      key: dynamicKey,
      expiresIn: 30000 // 30 seconds
    });

  } catch (err) {
    console.error("Internal key error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
}

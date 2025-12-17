import crypto from "crypto";

// ============================
// 🔥 Anti-Scraping Protection for Courses API
// ============================

// Rate limiting store
const requestCounts = new Map();

function getClientIP(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.connection?.remoteAddress || "unknown";
}

function isRateLimited(identifier, maxRequests = 10, windowMs = 60000) {
  const now = Date.now();

  if (!requestCounts.has(identifier)) {
    requestCounts.set(identifier, []);
  }

  const requests = requestCounts.get(identifier).filter(time => time > now - windowMs);
  requests.push(now);
  requestCounts.set(identifier, requests);

  return requests.length > maxRequests;
}

function verifyInternalRequest(req) {
  // STRICT: Only allow internal server-to-server requests
  const apiKey = req.headers["x-api-key"];
  const internalFlag = req.headers["x-internal-request"];

  // Must have correct API key
  if (!apiKey || apiKey !== process.env.SECRET_KEY) {
    return false;
  }

  // Must have internal flag
  if (internalFlag !== "true") {
    return false;
  }

  // Check that request comes from allowed origin (same server)
  const origin = req.headers["origin"] || "";
  const referer = req.headers["referer"] || "";
  const siteUrl = process.env.SITE_URL || "";

  // Internal requests should NOT have origin/referer from external sources
  // They should come from the same server
  if (origin && siteUrl) {
    try {
      const originHost = new URL(origin).host;
      const siteHost = new URL(siteUrl).host;
      // If origin is present, it must match our site
      if (originHost !== siteHost) {
        return false;
      }
    } catch {
      return false;
    }
  }

  return true;
}

export default function handler(req, res) {
  const ip = getClientIP(req);

  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cache-Control", "private, no-store, no-cache");

  // ============================
  // 🔥 Block ALL external requests
  // ============================

  // This endpoint should ONLY be called internally by proxy.js
  // Block ALL direct access from browsers, curl, Python, etc.

  if (!verifyInternalRequest(req)) {
    // Log blocked attempts
    console.warn(`[COURSES_BLOCKED] Unauthorized access attempt from IP: ${ip}`, {
      userAgent: req.headers["user-agent"]?.substring(0, 100),
      origin: req.headers["origin"],
      referer: req.headers["referer"],
      timestamp: new Date().toISOString()
    });

    // Return generic 404 to hide the endpoint's existence
    return res.status(404).json({ error: "Not found" });
  }

  // Rate limiting for internal requests too
  if (isRateLimited("internal-api", 30, 60000)) {
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  try {
    // Load data
    const data = require("../data/coursatk_scraped_data.json");

    // Generate random IV for each request
    const key = Buffer.from(process.env.DATA_KEY, "hex");
    const iv = crypto.randomBytes(12); // 12 bytes for GCM

    // Encrypt with AES-256-GCM for authenticated encryption
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    let encrypted = cipher.update(JSON.stringify(data), "utf8", "hex");
    encrypted += cipher.final("hex");

    // Get authentication tag
    const authTag = cipher.getAuthTag();

    res.status(200).json({
      iv: iv.toString("hex"),
      data: encrypted,
      tag: authTag.toString("hex"),
      algorithm: "aes-256-gcm"
    });

  } catch (err) {
    console.error("Courses API error:", err.message);
    res.status(500).json({ error: "Internal error" });
  }
}

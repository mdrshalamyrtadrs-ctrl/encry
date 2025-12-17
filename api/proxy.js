import crypto from "crypto";

// ============================
// 🔥 Anti-Scraping Protection
// ============================

// Rate limiting store
const rateLimitStore = new Map();
const challengeStore = new Map();

function getClientIP(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.connection?.remoteAddress || "unknown";
}

function isRateLimited(ip, maxRequests = 5, windowMs = 60000) {
  const now = Date.now();
  const windowStart = now - windowMs;

  if (!rateLimitStore.has(ip)) {
    rateLimitStore.set(ip, []);
  }

  const requests = rateLimitStore.get(ip).filter(time => time > windowStart);
  requests.push(now);
  rateLimitStore.set(ip, requests);

  return requests.length > maxRequests;
}

// Generate challenge for browser verification
function generateChallenge() {
  const challengeId = crypto.randomUUID();
  const timestamp = Date.now();
  const secret = crypto.randomBytes(16).toString("hex");

  // Challenge expires in 30 seconds
  challengeStore.set(challengeId, {
    secret,
    timestamp,
    expiresAt: timestamp + 30000
  });

  // Cleanup old challenges
  for (const [id, data] of challengeStore) {
    if (Date.now() > data.expiresAt) {
      challengeStore.delete(id);
    }
  }

  return { challengeId, secret };
}

function verifyChallenge(challengeId, response, expectedResult) {
  const challenge = challengeStore.get(challengeId);

  if (!challenge) return false;
  if (Date.now() > challenge.expiresAt) {
    challengeStore.delete(challengeId);
    return false;
  }

  // Verify the response matches expected computation
  const expected = crypto
    .createHmac("sha256", challenge.secret)
    .update(expectedResult)
    .digest("hex");

  challengeStore.delete(challengeId);

  try {
    return crypto.timingSafeEqual(
      Buffer.from(response, "hex"),
      Buffer.from(expected, "hex")
    );
  } catch {
    return false;
  }
}

function verifyBrowserFingerprint(req) {
  // Check for headers that browsers send but scripts usually don't
  const requiredHeaders = [
    "accept",
    "accept-language",
    "accept-encoding"
  ];

  for (const header of requiredHeaders) {
    if (!req.headers[header]) {
      return false;
    }
  }

  // Check Accept header contains text/html (browsers) or specific app signature
  const accept = req.headers["accept"] || "";
  if (!accept.includes("text/html") && !accept.includes("application/json")) {
    return false;
  }

  return true;
}

function verifySessionToken(token, secret) {
  if (!token || !secret) return false;

  try {
    const [payloadB64, signature] = token.split(".");
    if (!payloadB64 || !signature) return false;

    const payload = Buffer.from(payloadB64, "base64").toString("utf8");

    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("hex");

    if (!crypto.timingSafeEqual(
      Buffer.from(signature, "hex"),
      Buffer.from(expectedSignature, "hex")
    )) {
      return false;
    }

    // Check expiry
    const [, , , timestamp] = payload.split(":");
    const tokenTime = parseInt(timestamp, 10);
    const now = Date.now();

    // Token valid for 24 hours
    if (isNaN(tokenTime) || now - tokenTime > 86400000) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

function verifyRequestSignature(signature, timestamp, secret) {
  if (!signature || !timestamp || !secret) return false;

  try {
    const now = Date.now();
    const signatureTime = parseInt(timestamp, 10);

    // Signature expires after 2 minutes (reduced from 5)
    if (isNaN(signatureTime) || Math.abs(now - signatureTime) > 120000) {
      return false;
    }

    const expectedSignature = crypto
      .createHmac("sha256", secret)
      .update(timestamp)
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(signature, "hex"),
      Buffer.from(expectedSignature, "hex")
    );
  } catch {
    return false;
  }
}

export default async function handler(req, res) {
  const ip = getClientIP(req);

  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");

  // ============================
  // 🔥 Block non-browser requests
  // ============================

  // Block requests without proper browser headers
  if (!verifyBrowserFingerprint(req)) {
    console.warn(`[BLOCKED] Missing browser headers from IP: ${ip}`);
    return res.status(403).json({ error: "Access denied" });
  }

  // ============================
  // 🔥 Rate Limiting
  // ============================
  if (isRateLimited(ip)) {
    console.warn(`[RATE_LIMITED] IP: ${ip}`);
    return res.status(429).json({ error: "Too many requests" });
  }

  // ============================
  // 🔥 Origin/Referer Check
  // ============================
  const origin = req.headers["origin"] || "";
  const referer = req.headers["referer"] || "";
  const siteUrl = process.env.SITE_URL || "";

  let isValidOrigin = false;

  if (siteUrl) {
    try {
      const siteHost = new URL(siteUrl).host;

      if (origin) {
        isValidOrigin = new URL(origin).host === siteHost;
      }
      if (!isValidOrigin && referer) {
        isValidOrigin = new URL(referer).host === siteHost;
      }
    } catch {
      isValidOrigin = false;
    }
  }

  if (!isValidOrigin) {
    console.warn(`[BLOCKED] Invalid origin from IP: ${ip}, Origin: ${origin}, Referer: ${referer}`);
    return res.status(403).json({ error: "Access denied" });
  }

  // ============================
  // 🔥 Session Token Validation
  // ============================
  const sessionToken = req.headers["x-session-token"];

  if (!verifySessionToken(sessionToken, process.env.SESSION_SECRET)) {
    console.warn(`[BLOCKED] Invalid session token from IP: ${ip}`);
    return res.status(401).json({ error: "Authentication required" });
  }

  // ============================
  // 🔥 Request Signature Validation
  // ============================
  const signature = req.headers["x-signature"];
  const timestamp = req.headers["x-timestamp"];

  if (!verifyRequestSignature(signature, timestamp, process.env.SIGNATURE_SECRET)) {
    console.warn(`[BLOCKED] Invalid signature from IP: ${ip}`);
    return res.status(403).json({ error: "Invalid request" });
  }

  // ============================
  // 🔥 Challenge-Response (optional extra layer)
  // ============================
  const challengeId = req.headers["x-challenge-id"];
  const challengeResponse = req.headers["x-challenge-response"];

  // If challenge headers present, verify them
  if (challengeId || challengeResponse) {
    if (!challengeId || !challengeResponse) {
      return res.status(403).json({ error: "Incomplete challenge" });
    }

    if (!verifyChallenge(challengeId, challengeResponse, timestamp)) {
      console.warn(`[BLOCKED] Failed challenge from IP: ${ip}`);
      return res.status(403).json({ error: "Challenge failed" });
    }
  }

  // ============================
  // 🔥 Fetch and decrypt data
  // ============================
  try {
    const response = await fetch(`${process.env.SITE_URL}/api/courses`, {
      headers: {
        "x-api-key": process.env.SECRET_KEY,
        "x-internal-request": "true"
      }
    });

    if (!response.ok) {
      return res.status(502).json({ error: "Upstream error" });
    }

    const encrypted = await response.json();

    // AES-256-GCM Decryption
    const key = Buffer.from(process.env.DATA_KEY, "hex");
    const iv = Buffer.from(encrypted.iv, "hex");
    const authTag = Buffer.from(encrypted.tag, "hex");
    const encryptedData = Buffer.from(encrypted.data, "hex");

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData, null, "utf8");
    decrypted += decipher.final("utf8");

    const jsonData = JSON.parse(decrypted);

    // Set CORS only for valid origin
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }

    res.status(200).json(jsonData);

  } catch (error) {
    console.error("Proxy error:", error.message);
    res.status(500).json({ error: "Server error" });
  }
}

// Export challenge generator for client-side use
export { generateChallenge };

import crypto from "crypto";

// Rate limiting store (in production, use Redis)
const loginAttempts = new Map();
const sessions = new Map();

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 900000; // 15 minutes
const SESSION_DURATION = 86400000; // 24 hours

function getClientIP(req) {
    return req.headers["x-forwarded-for"]?.split(",")[0] ||
        req.connection?.remoteAddress || "unknown";
}

function isLockedOut(ip) {
    const attempts = loginAttempts.get(ip);
    if (!attempts) return false;

    const now = Date.now();

    // Check if lockout has expired
    if (attempts.lockedUntil && now > attempts.lockedUntil) {
        loginAttempts.delete(ip);
        return false;
    }

    return attempts.count >= MAX_LOGIN_ATTEMPTS;
}

function recordFailedAttempt(ip) {
    const now = Date.now();
    const attempts = loginAttempts.get(ip) || { count: 0, firstAttempt: now };

    // Reset if first attempt was more than 15 minutes ago
    if (now - attempts.firstAttempt > LOCKOUT_DURATION) {
        loginAttempts.set(ip, { count: 1, firstAttempt: now });
        return;
    }

    attempts.count++;

    if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
        attempts.lockedUntil = now + LOCKOUT_DURATION;
    }

    loginAttempts.set(ip, attempts);
}

function clearFailedAttempts(ip) {
    loginAttempts.delete(ip);
}

function generateSessionToken(userId, deviceId) {
    const sessionId = crypto.randomUUID();
    const timestamp = Date.now();
    const payload = `${sessionId}:${userId}:${deviceId}:${timestamp}`;

    const signature = crypto
        .createHmac("sha256", process.env.SESSION_SECRET)
        .update(payload)
        .digest("hex");

    const token = `${Buffer.from(payload).toString("base64")}.${signature}`;

    // Store session
    sessions.set(sessionId, {
        userId,
        deviceId,
        createdAt: timestamp,
        expiresAt: timestamp + SESSION_DURATION
    });

    return { token, sessionId, expiresAt: timestamp + SESSION_DURATION };
}

function verifySessionToken(token) {
    if (!token) return null;

    try {
        const [payloadB64, signature] = token.split(".");
        const payload = Buffer.from(payloadB64, "base64").toString("utf8");

        // Verify signature
        const expectedSignature = crypto
            .createHmac("sha256", process.env.SESSION_SECRET)
            .update(payload)
            .digest("hex");

        if (!crypto.timingSafeEqual(
            Buffer.from(signature, "hex"),
            Buffer.from(expectedSignature, "hex")
        )) {
            return null;
        }

        const [sessionId, userId, deviceId, timestamp] = payload.split(":");
        const session = sessions.get(sessionId);

        if (!session || Date.now() > session.expiresAt) {
            sessions.delete(sessionId);
            return null;
        }

        return { sessionId, userId, deviceId };
    } catch {
        return null;
    }
}

function generateSecurePassword(code) {
    // Generate a proper password hash instead of using the code directly
    return crypto
        .pbkdf2Sync(code, process.env.PASSWORD_SALT || "default-salt", 100000, 64, "sha512")
        .toString("hex");
}

export default async function handler(req, res) {
    // Security headers
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Cache-Control", "no-store");

    const ip = getClientIP(req);

    // Handle different auth actions
    const action = req.query.action || req.body?.action;

    switch (action) {
        case "login":
            return handleLogin(req, res, ip);
        case "verify":
            return handleVerify(req, res);
        case "logout":
            return handleLogout(req, res);
        default:
            return res.status(400).json({ error: "Invalid action" });
    }
}

async function handleLogin(req, res, ip) {
    // Check lockout
    if (isLockedOut(ip)) {
        return res.status(429).json({
            error: "Too many failed attempts. Please try again later.",
            retryAfter: LOCKOUT_DURATION / 1000
        });
    }

    const { code, deviceId } = req.body || {};

    // Validate input
    if (!code || typeof code !== "string" || !/^\d{9}$/.test(code)) {
        recordFailedAttempt(ip);
        return res.status(400).json({ error: "Invalid code format" });
    }

    if (!deviceId || typeof deviceId !== "string") {
        return res.status(400).json({ error: "Device ID required" });
    }

    try {
        // Verify code with your backend/Google Apps Script
        const verifyUrl = process.env.AUTH_API_URL;
        const verifyResponse = await fetch(
            `${verifyUrl}?action=check&code=${encodeURIComponent(code)}&device=${encodeURIComponent(deviceId)}`,
            { signal: AbortSignal.timeout(10000) }
        );

        if (!verifyResponse.ok) {
            recordFailedAttempt(ip);
            return res.status(401).json({ error: "Authentication failed" });
        }

        const userData = await verifyResponse.json();

        if (userData.result !== "success") {
            recordFailedAttempt(ip);
            return res.status(401).json({ error: userData.message || "Invalid code" });
        }

        // Clear failed attempts on success
        clearFailedAttempts(ip);

        // Generate secure session
        const session = generateSessionToken(code, deviceId);

        // Return session token (not the raw code!)
        return res.status(200).json({
            success: true,
            sessionToken: session.token,
            expiresAt: session.expiresAt,
            user: {
                name: userData.name,
                section: userData.section,
                endDate: userData.end_date
            }
        });

    } catch (err) {
        console.error("Login error:", err.message);
        return res.status(500).json({ error: "Authentication service unavailable" });
    }
}

async function handleVerify(req, res) {
    const token = req.headers["authorization"]?.replace("Bearer ", "") ||
        req.query.token;

    const session = verifySessionToken(token);

    if (!session) {
        return res.status(401).json({ error: "Invalid or expired session" });
    }

    return res.status(200).json({
        valid: true,
        sessionId: session.sessionId
    });
}

async function handleLogout(req, res) {
    const token = req.headers["authorization"]?.replace("Bearer ", "");

    if (token) {
        try {
            const [payloadB64] = token.split(".");
            const payload = Buffer.from(payloadB64, "base64").toString("utf8");
            const [sessionId] = payload.split(":");
            sessions.delete(sessionId);
        } catch {
            // Ignore errors during logout
        }
    }

    return res.status(200).json({ success: true });
}

// Export helpers for other modules
export { verifySessionToken, generateSecurePassword };

# 🔐 Security Implementation Guide

## Overview

This document describes the security measures implemented in the platform to protect against common vulnerabilities.

## Changes Made

### 1. **Authentication System** (`api/auth.js`)

#### Features:
- **Rate limiting**: 5 login attempts per 15 minutes before lockout
- **Cryptographic session tokens**: HMAC-SHA256 signed tokens
- **Secure password hashing**: PBKDF2 with 100,000 iterations
- **Device fingerprinting**: Binds sessions to specific devices

#### Usage:
```javascript
// Login
const response = await fetch('/api/auth', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ action: 'login', code: '123456789', deviceId: 'fingerprint' })
});

// Verify session
const verifyResponse = await fetch('/api/auth?action=verify', {
  headers: { 'Authorization': 'Bearer <session_token>' }
});
```

---

### 2. **SSRF Protection** (`api/stream.js`)

#### Before (Vulnerable):
```javascript
const url = req.query.url;
const response = await fetch(url); // No validation!
```

#### After (Secure):
```javascript
const ALLOWED_DOMAINS = ['cdn.example.com', 'media.example.com'];

function isAllowedUrl(urlString) {
  const url = new URL(urlString);
  if (url.protocol !== 'https:') return false;
  return ALLOWED_DOMAINS.some(domain => url.hostname.endsWith(domain));
}
```

**⚠️ ACTION REQUIRED**: Update `ALLOWED_DOMAINS` in `api/stream.js` with your actual CDN domains.

---

### 3. **Request Signing** (`api/proxy.js`)

All API requests now require:
- `x-signature`: HMAC-SHA256 signature
- `x-timestamp`: Request timestamp (5-minute validity)
- `x-session-token`: Valid session token

---

### 4. **Encryption Upgrade** (`api/courses.js`)

- Upgraded from AES-256-CBC to **AES-256-GCM** (authenticated encryption)
- Prevents tampering with encrypted data

---

### 5. **Client-Side Security** (`secure-auth.js`)

- Session tokens stored in `sessionStorage` (not `localStorage`)
- Automatic session monitoring and refresh
- Device fingerprinting for session binding
- XSS prevention with HTML escaping

---

### 6. **Security Headers** (`vercel.json`)

Added headers on all routes:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

---

### 7. **Content Security Policy** (HTML files)

All HTML pages now include CSP headers restricting:
- Script sources to `'self'`
- Connections to `'self'` and `/api/`
- Fonts to Google Fonts only

---

## Environment Variables

Create a `.env.local` file with these variables:

| Variable | Description | How to Generate |
|----------|-------------|-----------------|
| `SITE_URL` | Your deployment URL | `https://your-site.vercel.app` |
| `SECRET_KEY` | API authentication key | `openssl rand -hex 32` |
| `DATA_KEY` | AES encryption key (32 bytes) | `openssl rand -hex 32` |
| `SESSION_SECRET` | Session token signing key | `openssl rand -hex 32` |
| `SIGNATURE_SECRET` | Request signature key | `openssl rand -hex 32` |
| `STREAM_SECRET` | Video stream token key | `openssl rand -hex 32` |
| `INTERNAL_KEY` | Dynamic key generation | `openssl rand -hex 32` |
| `PASSWORD_SALT` | Password hashing salt | `openssl rand -hex 16` |
| `AUTH_API_URL` | Your auth backend URL | Your Google Apps Script URL |

---

## Security Checklist

- [ ] Set all environment variables in Vercel dashboard
- [ ] Update `ALLOWED_DOMAINS` in `api/stream.js` with your CDN domains
- [ ] Remove or move `data/coursatk_scraped_data.json` to a secure location
- [ ] Enable Vercel's built-in DDoS protection
- [ ] Set up monitoring for failed login attempts
- [ ] Rotate API keys regularly
- [ ] Test all authentication flows

---

## Removed Vulnerabilities

| Vulnerability | Status | Fix |
|--------------|--------|-----|
| Exposed Firebase credentials | ✅ Fixed | Removed from client-side |
| SSRF in stream.js | ✅ Fixed | URL whitelist validation |
| Weak password (code=password) | ✅ Fixed | PBKDF2 hashing |
| Bypassable signature check | ✅ Fixed | HMAC-SHA256 verification |
| No rate limiting | ✅ Fixed | Login attempt limits |
| Client-side auth bypass | ✅ Fixed | Server-side session validation |
| Overly permissive CORS | ✅ Fixed | Origin whitelist |
| XSS via user data | ✅ Fixed | HTML escaping |

---

## Testing Security

1. **Test rate limiting**:
   ```bash
   for i in {1..10}; do curl -X POST /api/auth -d '{"action":"login","code":"wrong"}'; done
   ```

2. **Test SSRF protection**:
   ```bash
   curl "/api/stream?url=http://localhost:3000/internal"
   # Should return 403 Forbidden
   ```

3. **Test session expiry**:
   - Login and wait 24 hours
   - Verify automatic logout

---

## Support

If you find additional security issues, please report them immediately.

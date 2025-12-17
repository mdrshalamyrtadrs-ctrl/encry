// ===========================
// token.js — Secure Client Script
// ===========================

const SecureAPI = {
  API_URL: "/api/proxy",

  /**
   * Get session token
   */
  getSessionToken() {
    const token = sessionStorage.getItem("session_token");
    const expires = parseInt(sessionStorage.getItem("session_expires"), 10);

    if (!token || !expires || Date.now() > expires) {
      return null;
    }

    return token;
  },

  /**
   * Generate request signature
   */
  async generateSignature(timestamp) {
    // Get dynamic key from server
    const sessionToken = this.getSessionToken();

    if (!sessionToken) {
      throw new Error("Not authenticated");
    }

    const keyResponse = await fetch("/api/internal-key", {
      headers: {
        "Authorization": `Bearer ${sessionToken}`
      },
      cache: "no-store"
    });

    if (!keyResponse.ok) {
      throw new Error("Failed to get signature key");
    }

    const { key } = await keyResponse.json();

    // Generate signature using the dynamic key
    const encoder = new TextEncoder();
    const data = encoder.encode(`${timestamp}:${key}`);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  },

  /**
   * Fetch courses with proper authentication
   */
  async fetchCourses() {
    const sessionToken = this.getSessionToken();

    if (!sessionToken) {
      console.error("No valid session token");
      window.location.href = "index.html";
      return null;
    }

    try {
      const timestamp = Date.now().toString();
      const signature = await this.generateSignature(timestamp);

      const res = await fetch(this.API_URL, {
        method: "GET",
        headers: {
          "x-signature": signature,
          "x-timestamp": timestamp,
          "x-session-token": sessionToken,
          "x-client": "web-app"
        },
        cache: "no-store"
      });

      if (res.status === 401 || res.status === 403) {
        console.error("Authentication failed");
        sessionStorage.clear();
        window.location.href = "index.html";
        return null;
      }

      if (!res.ok) {
        throw new Error(`API error: ${res.status}`);
      }

      const data = await res.json();
      console.log("Courses loaded successfully");

      return data;
    } catch (err) {
      console.error("API Error:", err.message);
      return null;
    }
  }
};

// Public API
window.getCourses = () => SecureAPI.fetchCourses();
window.SecureAPI = SecureAPI;

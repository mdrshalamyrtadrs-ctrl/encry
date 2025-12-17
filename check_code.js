// ==========================
// check_code.js
// Secure session verification module
// ==========================

const SessionManager = {
  API_URL: "/api/auth",

  /**
   * Get session token from secure storage
   */
  getSessionToken() {
    const token = sessionStorage.getItem("session_token");
    const expires = parseInt(sessionStorage.getItem("session_expires"), 10);

    if (!token || !expires || Date.now() > expires) {
      this.clearSession();
      return null;
    }

    return token;
  },

  /**
   * Clear all session data
   */
  clearSession() {
    sessionStorage.removeItem("session_token");
    sessionStorage.removeItem("session_expires");
    localStorage.removeItem("user_name");
    localStorage.removeItem("user_section");
    localStorage.removeItem("user_code");
    localStorage.removeItem("user_data");
  },

  /**
   * Show notification toast
   */
  showToast(message, type = "error", duration = 4000) {
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.innerText = message;
    document.body.appendChild(toast);

    Object.assign(toast.style, {
      position: "fixed",
      bottom: "30px",
      left: "50%",
      transform: "translateX(-50%)",
      padding: "15px 25px",
      background: type === "success" ? "#4ade80" : "#f87171",
      color: "#fff",
      fontSize: "16px",
      borderRadius: "10px",
      boxShadow: "0 5px 20px rgba(0,0,0,0.3)",
      zIndex: 9999,
      opacity: 0,
      transition: "opacity 0.5s ease, bottom 0.5s ease"
    });

    setTimeout(() => { toast.style.opacity = 1; toast.style.bottom = "50px"; }, 50);

    setTimeout(() => {
      toast.style.opacity = 0;
      toast.style.bottom = "30px";
      setTimeout(() => toast.remove(), 500);
    }, duration);
  },

  /**
   * Verify session with server
   */
  async verifySession() {
    const token = this.getSessionToken();

    if (!token) {
      return { valid: false, reason: "no_token" };
    }

    try {
      const response = await fetch(`${this.API_URL}?action=verify`, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${token}`
        },
        cache: "no-store"
      });

      if (!response.ok) {
        return { valid: false, reason: "invalid_session" };
      }

      const data = await response.json();
      return { valid: data.valid === true, reason: data.valid ? null : "expired" };

    } catch (err) {
      console.error("[SessionManager] Verification error:", err);
      // On network error, check local expiry
      const expires = parseInt(sessionStorage.getItem("session_expires"), 10);
      if (expires && Date.now() < expires) {
        return { valid: true, reason: "offline_valid" };
      }
      return { valid: false, reason: "network_error" };
    }
  },

  /**
   * Auto-check session and redirect if invalid
   */
  async autoCheckSession(redirectPage = "index.html") {
    const result = await this.verifySession();

    if (!result.valid) {
      this.clearSession();

      let message = "⛔ الجلسة منتهية. الرجاء تسجيل الدخول مجدداً.";

      switch (result.reason) {
        case "no_token":
          message = "⛔ الرجاء تسجيل الدخول أولاً.";
          break;
        case "invalid_session":
          message = "⛔ الجلسة غير صالحة.";
          break;
        case "network_error":
          message = "⚠ خطأ في الاتصال بالخادم.";
          break;
      }

      this.showToast(message, "error", 3000);

      setTimeout(() => {
        window.location.href = redirectPage;
      }, 1000);

      return false;
    }

    return true;
  },

  /**
   * Setup periodic session refresh
   */
  setupAutoRefresh(intervalMs = 300000) { // 5 minutes
    setInterval(async () => {
      const isValid = await this.verifySession();
      if (!isValid.valid) {
        this.clearSession();
        window.location.href = "index.html";
      }
    }, intervalMs);
  }
};

/**
 * Run session check on page load
 */
window.addEventListener("DOMContentLoaded", () => {
  SessionManager.autoCheckSession();
  SessionManager.setupAutoRefresh();
});

// Export for use in other scripts
window.SessionManager = SessionManager;

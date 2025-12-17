// ===========================
// secure-auth.js
// Centralized secure authentication module
// ===========================

const SecureAuth = (function () {
    const AUTH_API = "/api/auth";
    const KEY_API = "/api/internal-key";

    // Private methods
    async function hashData(data) {
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(data));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    }

    async function generateDeviceFingerprint() {
        const components = [
            navigator.userAgent,
            navigator.language,
            screen.width + "x" + screen.height,
            new Date().getTimezoneOffset(),
            navigator.hardwareConcurrency || 0,
            navigator.platform || "unknown"
        ];
        return await hashData(components.join("|"));
    }

    // Public API
    return {
        // Session management
        getSessionToken() {
            const token = sessionStorage.getItem("session_token");
            const expires = parseInt(sessionStorage.getItem("session_expires"), 10);

            if (!token || !expires || Date.now() > expires) {
                this.clearSession();
                return null;
            }
            return token;
        },

        setSession(sessionData) {
            sessionStorage.setItem("session_token", sessionData.sessionToken);
            sessionStorage.setItem("session_expires", sessionData.expiresAt.toString());

            if (sessionData.user) {
                localStorage.setItem("user_name", sessionData.user.name || "");
                localStorage.setItem("user_section", sessionData.user.section || "");
                localStorage.setItem("user_end_date", sessionData.user.endDate || "");
            }
        },

        clearSession() {
            sessionStorage.removeItem("session_token");
            sessionStorage.removeItem("session_expires");
            localStorage.removeItem("user_name");
            localStorage.removeItem("user_section");
            localStorage.removeItem("user_end_date");
            localStorage.removeItem("user_code");
            localStorage.removeItem("user_data");
            localStorage.removeItem("access_token");
        },

        isAuthenticated() {
            return !!this.getSessionToken();
        },

        getUserInfo() {
            return {
                name: localStorage.getItem("user_name") || "",
                section: localStorage.getItem("user_section") || "",
                endDate: localStorage.getItem("user_end_date") || ""
            };
        },

        // Authentication
        async login(code) {
            if (!/^\d{9}$/.test(code)) {
                throw new Error("INVALID_CODE_FORMAT");
            }

            const deviceId = await generateDeviceFingerprint();

            const response = await fetch(AUTH_API, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    action: "login",
                    code: code,
                    deviceId: deviceId
                })
            });

            const data = await response.json();

            if (!response.ok) {
                if (response.status === 429) {
                    throw new Error("TOO_MANY_ATTEMPTS");
                }
                throw new Error(data.error || "LOGIN_FAILED");
            }

            if (data.success && data.sessionToken) {
                this.setSession(data);
            }

            return data;
        },

        async logout() {
            const token = this.getSessionToken();

            if (token) {
                try {
                    await fetch(`${AUTH_API}?action=logout`, {
                        method: "POST",
                        headers: {
                            "Authorization": `Bearer ${token}`
                        }
                    });
                } catch (e) {
                    console.warn("Logout request failed:", e.message);
                }
            }

            this.clearSession();
        },

        async verifySession() {
            const token = this.getSessionToken();

            if (!token) {
                return { valid: false, reason: "no_token" };
            }

            try {
                const response = await fetch(`${AUTH_API}?action=verify`, {
                    headers: {
                        "Authorization": `Bearer ${token}`
                    },
                    cache: "no-store"
                });

                if (!response.ok) {
                    return { valid: false, reason: "server_rejected" };
                }

                const data = await response.json();
                return { valid: data.valid === true };

            } catch (err) {
                // On network error, trust local expiry
                const expires = parseInt(sessionStorage.getItem("session_expires"), 10);
                if (expires && Date.now() < expires) {
                    return { valid: true, reason: "offline_trusted" };
                }
                return { valid: false, reason: "network_error" };
            }
        },

        // Request signing
        async generateRequestSignature(timestamp) {
            const token = this.getSessionToken();

            if (!token) {
                throw new Error("Not authenticated");
            }

            const keyResponse = await fetch(KEY_API, {
                headers: {
                    "Authorization": `Bearer ${token}`
                },
                cache: "no-store"
            });

            if (!keyResponse.ok) {
                if (keyResponse.status === 401) {
                    this.clearSession();
                    throw new Error("Session expired");
                }
                throw new Error("Failed to get signing key");
            }

            const { key } = await keyResponse.json();
            return await hashData(`${timestamp}:${key}`);
        },

        // Protected fetch
        async secureFetch(url, options = {}) {
            const token = this.getSessionToken();

            if (!token) {
                window.location.href = "index.html";
                throw new Error("Not authenticated");
            }

            const timestamp = Date.now().toString();
            const signature = await this.generateRequestSignature(timestamp);

            const headers = {
                ...options.headers,
                "x-signature": signature,
                "x-timestamp": timestamp,
                "x-session-token": token
            };

            const response = await fetch(url, {
                ...options,
                headers,
                cache: "no-store"
            });

            if (response.status === 401 || response.status === 403) {
                this.clearSession();
                window.location.href = "index.html";
                throw new Error("Authentication required");
            }

            return response;
        },

        // Page protection
        async protectPage(redirectUrl = "index.html") {
            const result = await this.verifySession();

            if (!result.valid) {
                this.clearSession();
                this.showToast("⛔ الرجاء تسجيل الدخول", "error");
                setTimeout(() => {
                    window.location.href = redirectUrl;
                }, 1000);
                return false;
            }

            return true;
        },

        // UI helpers
        showToast(message, type = "error", duration = 4000) {
            // Remove existing toasts
            document.querySelectorAll(".secure-auth-toast").forEach(t => t.remove());

            const toast = document.createElement("div");
            toast.className = "secure-auth-toast";
            toast.innerText = message;
            document.body.appendChild(toast);

            const bgColor = type === "success" ? "#4ade80" :
                type === "warning" ? "#fbbf24" : "#f87171";

            Object.assign(toast.style, {
                position: "fixed",
                bottom: "30px",
                left: "50%",
                transform: "translateX(-50%)",
                padding: "15px 25px",
                background: bgColor,
                color: "#fff",
                fontSize: "16px",
                fontFamily: "'Cairo', sans-serif",
                borderRadius: "10px",
                boxShadow: "0 5px 20px rgba(0,0,0,0.3)",
                zIndex: 99999,
                opacity: 0,
                transition: "opacity 0.4s ease, bottom 0.4s ease"
            });

            requestAnimationFrame(() => {
                toast.style.opacity = 1;
                toast.style.bottom = "50px";
            });

            setTimeout(() => {
                toast.style.opacity = 0;
                setTimeout(() => toast.remove(), 400);
            }, duration);
        },

        // Auto session refresh
        startSessionMonitor(intervalMs = 60000) {
            const checkSession = async () => {
                const result = await this.verifySession();
                if (!result.valid) {
                    this.clearSession();
                    this.showToast("⛔ انتهت الجلسة", "error");
                    setTimeout(() => {
                        window.location.href = "index.html";
                    }, 1500);
                }
            };

            // Check immediately
            checkSession();

            // Then periodically
            return setInterval(checkSession, intervalMs);
        }
    };
})();

// Export globally
window.SecureAuth = SecureAuth;
